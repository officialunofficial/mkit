//! The job driver: start, step and the kind-16 timer.

use super::{
    CONTENT_WINDOW, Failure, FenceV1, ForkEnv, ForkError, ForkJobV1, ForkResult, ForkSpec,
    JOB_TTL_MS, PackRow, Phase, SLICE_CALLS, SettleV1, binding, closure, copy, decode_job,
    encode_job, plan, publish, set, sets, settle,
};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::store::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, StoreError, Value, keys,
};
use crate::timers::registry::{TimerHandler, TimerKind, kinds};
use crate::timers::{DueTimer, Fired, TimerCtx};

/// Calls below which a driver loop stops starting new steps.
const STEP_RESERVE: u32 = 40;

/// How a start request found the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartOutcome {
    /// This request created the job.
    Started(Box<ForkJobV1>),
    /// A job with the same binding already existed (a resume or a replay).
    Existing(Box<ForkJobV1>),
}

impl StartOutcome {
    /// The job either way.
    #[must_use]
    pub fn job(&self) -> &ForkJobV1 {
        match self {
            Self::Started(job) | Self::Existing(job) => job,
        }
    }
}

/// Create the destination's job, after checking the source's published pair
/// and that the destination is empty. The caller has authorized the request;
/// every refusal here is the uniform answer of [`ForkError`]. `settle` binds
/// the request's admission to the new job; when the same fork already exists
/// ([`StartOutcome::Existing`]) it is not used, and the caller must settle
/// the reservation it made itself.
///
/// # Errors
/// [`ForkError`].
pub async fn start<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
    settle: Option<SettleV1>,
) -> Result<StartOutcome, ForkError> {
    start_with(env, spec, settle, None).await
}

/// [`start`] with the authority facts the request was authorized under: the
/// job re-checks them when it registers the destination, however long after
/// the request that is.
///
/// # Errors
/// [`ForkError`].
pub async fn start_with<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
    settle: Option<SettleV1>,
    fence: Option<FenceV1>,
) -> Result<StartOutcome, ForkError> {
    // A map that cannot list its index shards cannot be forked from or into.
    if env.shards.object_index_partitions(&spec.source).is_empty()
        || env.shards.object_index_partitions(&spec.dest).is_empty()
    {
        return Err(ForkError::Unavailable("fork shard map"));
    }
    let wanted = binding(spec);
    let p = env.shards.coordinator(&spec.dest.namespace);
    let key = keys::fork_job(&spec.dest.name);
    if let Some(raw) = env.store.get(&p, &key).await? {
        let job = decode_job(&raw)?;
        return if job.binding == wanted {
            Ok(StartOutcome::Existing(Box::new(job)))
        } else {
            Err(ForkError::NotEmpty)
        };
    }
    let view = plan::read_source(
        env.store,
        env.shards,
        &spec.source,
        &spec.source_ref,
        &spec.expected_tip,
    )
    .await?;
    require_empty(env, &spec.dest, true).await?;
    require_unregistered(env, &spec.dest).await?;
    let now = env.now();
    check_request(env, &p, now, settle.as_ref(), fence.as_ref()).await?;
    // Quota binds here, with the job: the charge commits in the batch that
    // creates it, so a fork the window cannot hold is refused before any work.
    let (charge_pre, charge_writes, settle) = match settle {
        Some(mut settle) => {
            let (pre, writes) = settle::charge(env, &p, &settle, now).await?;
            settle.charges.clear();
            (pre, writes, Some(settle))
        }
        None => (Vec::new(), Vec::new(), None),
    };
    let job = ForkJobV1 {
        binding: wanted,
        dest_ns: spec.dest.namespace.as_str().to_owned(),
        dest_repo: spec.dest.name.as_str().to_owned(),
        source_ns: spec.source.namespace.as_str().to_owned(),
        source_repo: spec.source.name.as_str().to_owned(),
        source_ref: spec.source_ref.clone(),
        tip: spec.expected_tip,
        packmap: view.packmap,
        source_sequence: view.sequence,
        source_generation: view.generation,
        visibility: spec.visibility_name().to_owned(),
        created_ms: now,
        expires_ms: now.saturating_add(JOB_TTL_MS),
        phase: Phase::Plan,
        packs: vec![PackRow {
            id: view.packmap,
            len: 0,
            objects: 0,
            node: false,
            base: false,
        }],
        cursor: 0,
        deps: Vec::new(),
        part: 0,
        after: None,
        scanned: 0,
        copied: 0,
        failure: None,
        settle,
        fence,
        result: None,
    };
    let mut batch = Batch::new();
    batch.preconditions.extend(charge_pre);
    batch.writes.extend(charge_writes);
    let batch = batch
        .require(Precondition::NotAfter(now.saturating_add(CONTENT_WINDOW)))
        .require(Precondition::Absent(key.clone()))
        .put(key.clone(), encode_job(&job)?)
        .put(
            keys::timer(now, kinds::FORK.get(), key.as_bytes()),
            Value::default(),
        );
    create(env, &p, &key, batch, job).await
}

/// Commit the job's creation batch and decide whose job it is.
async fn create<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    p: &Partition,
    key: &crate::store::Key,
    batch: Batch,
    job: ForkJobV1,
) -> Result<StartOutcome, ForkError> {
    let applied = match env.store.apply(p, batch).await {
        Ok(applied) => applied,
        Err(error) => {
            // A reply can be lost after the batch committed, and the charge
            // and the reservation then belong to a job that exists: our own
            // row, found again, is a start.
            let ours = |existing: &ForkJobV1| {
                existing.binding == job.binding
                    && existing.created_ms == job.created_ms
                    && existing.settle.as_ref().map(|s| &s.rid)
                        == job.settle.as_ref().map(|s| &s.rid)
            };
            return match env.store.get(p, key).await {
                Ok(Some(raw)) if decode_job(&raw).is_ok_and(|existing| ours(&existing)) => {
                    Ok(StartOutcome::Started(Box::new(job)))
                }
                _ => Err(error.into()),
            };
        }
    };
    match applied {
        BatchOutcome::Committed => Ok(StartOutcome::Started(Box::new(job))),
        BatchOutcome::PreconditionFailed { .. } => {
            let raw = env
                .store
                .get(p, key)
                .await?
                .ok_or(ForkError::Unavailable("fork start contended"))?;
            let existing = decode_job(&raw)?;
            if existing.binding == job.binding {
                Ok(StartOutcome::Existing(Box::new(existing)))
            } else {
                Err(ForkError::NotEmpty)
            }
        }
        BatchOutcome::DeadlinePassed { .. } => Err(ForkError::Unavailable("fork start deadline")),
    }
}

/// What a request must carry for the job to run safely long after it: the
/// authority fence a persisted authority row requires, and a reservation the
/// reconciler will not abort under the running job.
async fn check_request<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    coordinator: &Partition,
    now: u64,
    settle: Option<&SettleV1>,
    fence: Option<&FenceV1>,
) -> Result<(), ForkError> {
    if fence.is_none_or(|f| f.authority_generation.is_none())
        && env
            .store
            .get(coordinator, &keys::authority_generation())
            .await?
            .is_some()
    {
        return Err(ForkError::Unavailable("fork requires authority fence"));
    }
    // The reconciler aborts a pending reservation at its reconcile time: it
    // must outlive the job, or the job would be failed under its feet.
    if let Some(settle) = settle.filter(|s| !s.rid.is_empty()) {
        match crate::store::codec::decode_reservation(&Value::new(settle.pending.clone())) {
            Ok(crate::store::codec::ReservationV1::Pending {
                reconcile_at_ms, ..
            }) if reconcile_at_ms > now.saturating_add(JOB_TTL_MS) => {}
            _ => return Err(ForkError::Unavailable("fork reservation")),
        }
    }
    Ok(())
}

/// A fork creates its destination: one that is already registered is not a
/// fork destination, so a fork never inherits a visibility it did not ask for.
async fn require_unregistered<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    dest: &RepoId,
) -> Result<(), ForkError> {
    let p = env.shards.coordinator(&dest.namespace);
    if env
        .store
        .get(&p, &keys::repo_record(&dest.name))
        .await?
        .is_some()
    {
        return Err(ForkError::NotEmpty);
    }
    Ok(())
}

/// A destination with any ref or member is not empty.
pub(super) async fn require_empty<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    dest: &RepoId,
    members: bool,
) -> Result<(), ForkError> {
    let (rs, re) = keys::ref_prefix_range(&dest.name, "");
    let (xs, xe) = keys::ref_index_prefix_range(&dest.name, "");
    let (ms, me) = keys::membership_repo_range(&dest.name);
    let mut partitions: Vec<(Partition, _, _)> = Vec::new();
    for p in env.shards.ref_index_partitions(dest) {
        if matches!(p, Partition::Namespace(_)) {
            partitions.push((p.clone(), rs.clone(), re.clone()));
        }
        partitions.push((p, xs.clone(), xe.clone()));
    }
    for p in env.shards.object_index_partitions(dest) {
        if members {
            partitions.push((p, ms.clone(), me.clone()));
        }
    }
    if partitions.is_empty() {
        return Err(ForkError::Unavailable("fork shard map"));
    }
    for (p, start, end) in partitions {
        if !env
            .store
            .scan(&p, &start, &end, None, 1)
            .await?
            .entries
            .is_empty()
        {
            return Err(ForkError::NotEmpty);
        }
    }
    Ok(())
}

/// What a driver call left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// The job as last read, or as committed.
    pub job: ForkJobV1,
    /// Whether any state was committed.
    pub progressed: bool,
}

/// Advance the destination's job until it finishes or `budget` is spent.
///
/// A terminal refusal is recorded in the job (and aborts its reservation).
/// One that arises before the destination was registered deletes the job
/// row instead, so the destination stays clean and the request can be
/// retried; the returned report still carries the failure.
///
/// # Errors
/// A retryable [`ForkError::Unavailable`].
pub async fn step<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    dest: &RepoId,
    budget: &SliceBudget,
) -> Result<StepReport, ForkError> {
    let p = env.shards.coordinator(&dest.namespace);
    let key = keys::fork_job(&dest.name);
    let store = Budgeted::new(env.store, budget);
    let mut progressed = false;
    // A terminal failure found at commit (a batch over the store's limits).
    let mut forced: Option<ForkError> = None;
    loop {
        // A spent allowance reads the job once more outside the budget, only
        // to report it.
        let spent = budget.remaining() < STEP_RESERVE;
        let raw = if spent {
            env.store.get(&p, &key).await?
        } else {
            store.get(&p, &key).await?
        }
        .ok_or(ForkError::Unavailable("fork job missing"))?;
        let mut job = decode_job(&raw).map_err(|_| ForkError::Unavailable("fork job corrupt"))?;
        if job.finished() || spent {
            return Ok(StepReport { job, progressed });
        }
        let before = job.clone();
        let mut outcome = match forced.take() {
            Some(error) => Err(error),
            None => advance(env, &mut job, budget).await,
        };
        let mut encoded = None;
        if outcome.is_ok() {
            match encode_job(&job) {
                Ok(value) => encoded = Some(value),
                // A row that cannot fit is a bound of the implementation.
                Err(StoreError::Invalid(_)) => outcome = Err(ForkError::TooLarge),
                Err(error) => return Err(error.into()),
            }
        }
        let (effects, row) = match outcome {
            Ok(effects) => (effects, encoded),
            Err(error) if super::spent(&error, budget) => {
                return Ok(StepReport {
                    job: before,
                    progressed,
                });
            }
            Err(error) => {
                let Some(failure) = Failure::of(&error) else {
                    return Err(error);
                };
                job = before.clone();
                terminate(env, &mut job, &error, failure).await?
            }
        };
        if row.is_some() && effects.writes.is_empty() && effects.preconditions.is_empty() {
            // A phase that yielded with nothing to record.
            if encode_job(&before)? == encode_job(&job)? {
                return Ok(StepReport { job, progressed });
            }
        }
        let batch = effects
            .require(Precondition::NotAfter(
                env.now().saturating_add(CONTENT_WINDOW),
            ))
            .require(Precondition::Equals(key.clone(), raw));
        let batch = match row {
            Some(value) => batch.put(key.clone(), value),
            None => batch.delete(key.clone()),
        };
        // The commit of a unit is settlement: it is not charged to the slice,
        // so a unit that spent the allowance can still record its progress.
        let applied = match env.store.apply(&p, batch).await {
            // A batch over the store's limits is a bound of the implementation.
            Err(StoreError::Invalid(_)) if forced.is_none() => {
                forced = Some(ForkError::TooLarge);
                continue;
            }
            other => other?,
        };
        match applied {
            BatchOutcome::Committed => {
                progressed = true;
                if job.finished() {
                    return Ok(StepReport { job, progressed });
                }
            }
            BatchOutcome::PreconditionFailed { .. } => {
                // Another driver advanced the job; its state is the truth.
                // Only committed state is reported.
                if budget.remaining() < STEP_RESERVE {
                    return Ok(StepReport {
                        job: before,
                        progressed,
                    });
                }
            }
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(ForkError::Unavailable("fork commit deadline"));
            }
        }
    }
}

/// End the job on a terminal refusal: abort its reservation, drop the scratch
/// sets (nothing may rely on them: a cleared set without the flag is never
/// read, and a flag without its set means a full walk) and either
/// record the failure or, before the destination was registered, delete the
/// row. Returns the effects and the row to put, if any.
async fn terminate<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    error: &ForkError,
    failure: Failure,
) -> Result<(Batch, Option<Value>), ForkError> {
    let detail = error.error().public_message().to_owned();
    let registered = !matches!(
        job.phase,
        Phase::Plan | Phase::Trees | Phase::Walk | Phase::Register
    );
    job.phase = Phase::Failed;
    job.failure = Some(failure);
    let reason = if matches!(error, ForkError::Moved(_)) {
        crate::store::codec::AbortReason::EpochMismatch
    } else {
        crate::store::codec::AbortReason::Unspecified
    };
    // A terminal row is small enough to always commit: the pack list is not
    // needed once the job has failed.
    job.packs.clear();
    job.deps.clear();
    let aborted = settle::abort(env, job, env.now(), &detail, reason).await?;
    let effects = sets::discard(aborted, &job.dest()?.name, &ALL_SETS);
    Ok((effects, registered.then(|| encode_job(job)).transpose()?))
}

const ALL_SETS: [u8; 5] = [
    set::CLEARED,
    set::TREES,
    set::QUEUE,
    set::BASES,
    set::MANIFESTS,
];

/// One state's unit of work; returns the coordinator effects to commit with
/// the updated job row.
async fn advance<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<Batch, ForkError> {
    let now = env.now();
    if now > job.expires_ms || !settle::current(env, job).await? {
        return Err(ForkError::Expired);
    }
    match job.phase {
        Phase::Plan => {
            if plan::slice(env, job, budget).await? {
                // The charge was an upper bound read at admission: a set that
                // outgrew it is not covered.
                if job
                    .settle
                    .as_ref()
                    .is_some_and(|s| job.pack_bytes() > s.declared_bytes)
                {
                    return Err(ForkError::Quota(super::OVER_ADMITTED));
                }
                job.phase = Phase::Trees;
                job.cursor = 0;
                job.deps.clear();
            }
            Ok(Batch::new())
        }
        Phase::Trees => {
            let (batch, done) = closure::trees(env, job, budget).await?;
            if done {
                job.phase = Phase::Walk;
                job.cursor = 0;
            }
            Ok(batch)
        }
        Phase::Walk => {
            let (batch, done) = closure::walk(env, job, budget).await?;
            if done {
                job.phase = Phase::Register;
            }
            Ok(batch)
        }
        Phase::Register => {
            // Anything that appeared since the job began ends the fork before
            // the destination is written, and so does a source too large to scan.
            require_empty(env, &job.dest()?, true).await?;
            require_unregistered(env, &job.dest()?).await?;
            copy::require_scannable(env, job, budget).await?;
            let batch = copy::register(env, job).await?;
            job.phase = Phase::Copy;
            job.part = 0;
            job.after = None;
            Ok(batch)
        }
        Phase::Copy => {
            if copy::copy(env, job, budget).await? {
                job.phase = Phase::Count;
                job.cursor = 0;
            }
            Ok(Batch::new())
        }
        Phase::Count => {
            let batch = copy::count(env, job, budget).await?;
            if job.cursor as usize >= job.packs.len() {
                job.phase = Phase::Publish;
                job.cursor = 0;
                job.part = 0;
                job.after = None;
            }
            Ok(batch)
        }
        Phase::Publish => {
            if job.cursor == 0 {
                // Members are written under guards of their own; a ref that a
                // racing writer created is the one change they cannot see.
                require_empty(env, &job.dest()?, false).await?;
            }
            if !publish::slice(env, job, budget).await? {
                return Ok(Batch::new());
            }
            job.result = Some(ForkResult {
                source: crate::store::repo_storage::identity(
                    &NamespaceKey::from_stored(job.source_ns.clone()),
                    &RepoName::new(job.source_repo.clone()).map_err(|_| ForkError::NotFound)?,
                ),
                source_ref: job.source_ref.clone(),
                tip: job.tip,
                source_sequence: job.source_sequence,
                packmap: job.packmap,
                pack_count: job.packs.len() as u64,
                pack_bytes: job.pack_bytes(),
                object_count: job.copied,
                pack_set: job.pack_set(),
                membership_generation: super::MEMBERSHIP_GENERATION,
            });
            job.phase = Phase::Done;
            // The walk's scratch sets go; the cleared set and the inherited
            // base packs stay as the boundary.
            let committed = settle::commit(env, job, now).await?;
            Ok(sets::discard(
                committed,
                &job.dest()?.name,
                &[set::TREES, set::QUEUE, set::MANIFESTS],
            ))
        }
        Phase::Done | Phase::Failed => Ok(Batch::new()),
    }
}

/// The kind-16 handler. It owns a handle to the whole namespace store, since
/// a fork writes many partitions; the timer row lives in the coordinator.
pub struct ForkTimer<N> {
    /// Reaches every partition.
    pub store: N,
    /// The deployment's shard map.
    pub shards: std::sync::Arc<dyn crate::pipeline::ShardMap>,
    /// The business clock.
    pub clock: std::sync::Arc<dyn crate::rt::Clock>,
    /// Whether pack-level takedown denial is on.
    pub takedown_denial: bool,
    /// The extraction threshold, if extraction is deployed.
    pub extract_min_bytes: Option<u64>,
}

impl<N> core::fmt::Debug for ForkTimer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForkTimer").finish_non_exhaustive()
    }
}

impl<S: NamespaceStore, N: NamespaceStore> TimerHandler<S> for ForkTimer<N> {
    fn kind(&self) -> TimerKind {
        kinds::FORK
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> crate::rt::BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let bad = || StoreError::Corrupt("invalid fork timer".into());
            let Some(keys::ParsedKey::ForkJob(name)) =
                keys::parse(&crate::store::Key::new(timer.reference.clone()))
            else {
                return Err(bad());
            };
            let Partition::Coordinator(ns) = ctx.partition else {
                return Err(bad());
            };
            let dest = RepoId {
                namespace: ns.clone(),
                name,
            };
            let env = ForkEnv {
                store: &self.store,
                shards: self.shards.as_ref(),
                clock: self.clock.as_ref(),
                takedown_denial: self.takedown_denial,
                extract_min_bytes: self.extract_min_bytes,
                limits: super::ForkLimits::default(),
            };
            let budget = SliceBudget::new(SLICE_CALLS);
            // A refusal before registration deletes the job: its timer ends.
            let job = keys::fork_job(&dest.name);
            if ctx.store.get(ctx.partition, &job).await?.is_none() {
                return Ok(Fired::Done(Batch::new()));
            }
            Ok(match step(&env, &dest, &budget).await {
                Ok(report) if report.job.finished() => Fired::Done(Batch::new()),

                Ok(_) => Fired::Reschedule {
                    due_at_ms: ctx.now_ms.saturating_add(1_000),
                    value: Value::default(),
                    batch: Batch::new(),
                },
                Err(_) => Fired::Reschedule {
                    due_at_ms: ctx.now_ms.saturating_add(crate::timers::RETRY_BACKOFF_MS),
                    value: Value::default(),
                    batch: Batch::new(),
                },
            })
        })
    }
}
