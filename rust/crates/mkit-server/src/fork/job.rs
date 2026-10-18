//! The job driver: start, step and the kind-16 timer.

use super::{
    CONTENT_WINDOW, Failure, FenceV1, ForkEnv, ForkError, ForkJobV1, ForkSpec, JOB_TTL_MS, PackRow,
    Phase, SLICE_CALLS, SettleV1, accept, binding, closure, copy, decode_job, encode_job, plan,
    publish, set, sets, settle,
};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::repo::RepoId;
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
/// job compares their exact observations at every advancing coordinator
/// commit, however long after the request that is.
///
/// # Errors
/// [`ForkError`].
pub async fn start_with<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
    settle: Option<SettleV1>,
    fence: Option<FenceV1>,
) -> Result<StartOutcome, ForkError> {
    start_planned(env, spec, settle, fence, None).await
}

/// [`start_with`] carrying the plan [`plan_fork`] computed for the same request.
///
/// A job created with a plan begins after its Plan phase. The plan is used
/// only if the source still publishes the pair it was computed from: the
/// tip, the packmap head and the membership generation are read again here
/// and any difference refuses the fork like a moved tip. Every other check
/// of [`start_with`] runs as before, and the pack proofs the Plan phase would
/// repeat next run at Publish.
///
/// # Errors
/// [`ForkError`].
pub async fn start_planned<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
    settle: Option<SettleV1>,
    fence: Option<FenceV1>,
    planned: Option<ForkPlan>,
) -> Result<StartOutcome, ForkError> {
    start_authorized(env, spec, settle, fence, planned, None).await
}

pub(crate) async fn start_authorized<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
    settle: Option<SettleV1>,
    fence: Option<FenceV1>,
    planned: Option<ForkPlan>,
    source_access: Option<super::SourceAccessV1>,
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
    super::proof::require_versioned_source(env, &spec.source)?;
    let view = plan::read_source(
        env.store,
        env.shards,
        &spec.source,
        &spec.source_ref,
        &spec.expected_tip,
    )
    .await
    .map_err(|error| {
        if source_access.is_some() && error == ForkError::TipChanged {
            ForkError::NotFound
        } else {
            error
        }
    })?;
    require_empty(env, &spec.dest, true).await?;
    require_unregistered(env, &spec.dest).await?;
    let now = env.now();
    check_request(env, &p, now, settle.as_ref(), fence.as_ref()).await?;
    let authority_rows = env
        .store
        .get_many(&p, &[keys::authority_generation(), keys::grant_epoch()])
        .await?;
    let [authority, epoch]: [_; 2] = authority_rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork fence read"))?;
    let mut checked_fence = fence.clone().unwrap_or(super::FenceV1 {
        authority_generation: None,
        grant_epoch: None,
        create_namespace: false,
    });
    // Namespace creation permission is still decided at registration; this
    // snapshot only validates the authority facts retained by the launch.
    checked_fence.create_namespace = true;
    copy::fence_guards(
        &checked_fence,
        (keys::authority_generation(), authority.as_ref()),
        (keys::grant_epoch(), epoch.as_ref()),
    )?;
    let current_access = super::SourceAccessV1::read(env.store, env.shards, &spec.source)
        .await?
        .with_policy(env.publication_policy, &spec.source)?;
    if source_access
        .as_ref()
        .is_some_and(|access| *access != current_access)
    {
        return Err(ForkError::NotFound);
    }
    let mut job = new_job(
        spec,
        &view,
        now,
        settle.clone().map(|mut s| {
            // The charges are applied by the creation batch, not carried.
            s.charges.clear();
            s.namespace_cap = None;
            s
        }),
        fence,
    );
    job.fence_rows = super::FenceRowsV1 {
        authority: authority.map(|v| v.as_bytes().to_vec()),
        epoch: epoch.map(|v| v.as_bytes().to_vec()),
    };
    job.source_access = current_access;
    if let Some(planned) = planned {
        planned.carry(&view, &mut job).map_err(|error| {
            if source_access.is_some() && error == ForkError::TipChanged {
                ForkError::NotFound
            } else {
                error
            }
        })?;
    }
    launch(env, &p, job, settle.as_ref()).await
}

/// The job a fork request starts, before its first step.
fn new_job(
    spec: &ForkSpec,
    view: &plan::SourceView,
    now: u64,
    settle: Option<SettleV1>,
    fence: Option<FenceV1>,
) -> ForkJobV1 {
    ForkJobV1 {
        binding: binding(spec),
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
        lanes: Vec::new(),
        after: None,
        scanned: 0,
        copied: 0,
        failure: None,
        settle,
        fence,
        fence_rows: crate::fork::FenceRowsV1::default(),
        source_access: crate::fork::SourceAccessV1::default(),
        proof: crate::fork::ProofV1::default(),
        accepted: None,
        result: None,
    }
}

/// The pack set a fork of one request inherits, computed before admission
/// and the pair of the source's published value it was computed from.
///
/// It is carried into the job by [`start_planned`], so the job does not plan
/// the same set again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkPlan {
    pub(super) packmap: mkit_core::hash::Hash,
    pub(super) generation: u64,
    pub(super) packs: Vec<PackRow>,
}

impl ForkPlan {
    /// The bytes the fork inherits: what admission is charged for.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.packs.iter().map(|p| p.len).sum()
    }

    /// Begin `job` after its Plan phase, if the source still publishes the
    /// pair this plan was computed from.
    pub(super) fn carry(
        self,
        view: &plan::SourceView,
        job: &mut ForkJobV1,
    ) -> Result<(), ForkError> {
        if view.packmap != self.packmap || view.generation != self.generation {
            return Err(ForkError::TipChanged);
        }
        job.packs = self.packs;
        // The Plan phase's own bound: admission charged exactly these bytes.
        if job.over_admitted() {
            return Err(ForkError::Quota(super::OVER_ADMITTED));
        }
        job.phase = Phase::Trees;
        job.cursor = 0;
        job.deps.clear();
        Ok(())
    }
}

/// The pack set a fork of `spec` would inherit, from the pack set of the
/// source's published value. The set is fixed by the tip the request pins
/// (sealed inventories are immutable). `None` when the plan does not fit one
/// slice, in which case the job plans it itself.
///
/// # Errors
/// The refusals of [`start`] that concern the source.
pub async fn plan_fork<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
) -> Result<Option<ForkPlan>, ForkError> {
    let view = plan::read_source(
        env.store,
        env.shards,
        &spec.source,
        &spec.source_ref,
        &spec.expected_tip,
    )
    .await?;
    let mut scratch = new_job(spec, &view, env.now(), None, None);
    let budget = SliceBudget::new(SLICE_CALLS);
    let complete = plan::slice(env, &mut scratch, &budget).await?;
    Ok(complete.then_some(ForkPlan {
        packmap: view.packmap,
        generation: view.generation,
        packs: scratch.packs,
    }))
}

/// The bytes a fork of `spec` would inherit: what admission is charged for,
/// the number the job's own plan reaches. `None` when the plan does not fit
/// one slice, in which case the caller falls back to an upper bound.
///
/// # Errors
/// The refusals of [`start`] that concern the source.
pub async fn plan_bytes<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    spec: &ForkSpec,
) -> Result<Option<u64>, ForkError> {
    Ok(plan_fork(env, spec).await?.as_ref().map(ForkPlan::bytes))
}

/// Creation attempts: the charge is planned against the quota rows as they
/// were read, so a concurrent write by the same signer loses the batch and
/// the charge is planned again.
const CREATE_ATTEMPTS: usize = 3;

/// Quota binds here, with the job: the charge commits in the batch that
/// creates it, so a fork the window cannot hold is refused before any work.
async fn launch<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    p: &Partition,
    job: ForkJobV1,
    charged: Option<&SettleV1>,
) -> Result<StartOutcome, ForkError> {
    let key = keys::fork_job(&job.dest()?.name);
    for attempt in 1..=CREATE_ATTEMPTS {
        let (pre, writes) = match charged {
            Some(settle) => settle::charge(env, p, settle, job.created_ms).await?,
            None => (Vec::new(), Vec::new()),
        };
        let mut batch = Batch::new();
        batch.preconditions.extend(pre);
        batch.preconditions.extend(job.fence_rows.guards(&job));
        if let Some(settle) = job.settle.as_ref().filter(|s| !s.rid.is_empty()) {
            batch.preconditions.push(Precondition::Equals(
                keys::reservation(&settle.rid)?,
                Value::new(settle.pending.clone()),
            ));
        }
        batch.writes.extend(writes);
        let batch = batch
            .require(Precondition::NotAfter(
                job.created_ms.saturating_add(CONTENT_WINDOW),
            ))
            .require(Precondition::Absent(key.clone()))
            .put(key.clone(), encode_job(&job)?)
            .put(
                keys::timer(job.created_ms, kinds::FORK.get(), key.as_bytes()),
                Value::default(),
            );
        match create(env, p, &key, batch, job.clone()).await {
            Err(ForkError::Unavailable(CONTENDED)) if attempt < CREATE_ATTEMPTS => {}
            other => return other,
        }
    }
    Err(ForkError::Unavailable(CONTENDED))
}

const CONTENDED: &str = "fork start contended";

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
                    && existing.settle.as_ref().map(|s| (&s.rid, &s.replay))
                        == job.settle.as_ref().map(|s| (&s.rid, &s.replay))
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
            let rows = env
                .store
                .get_many(
                    p,
                    &[
                        key.clone(),
                        keys::authority_generation(),
                        keys::grant_epoch(),
                    ],
                )
                .await?;
            let [raw, authority, epoch]: [_; 3] = rows
                .try_into()
                .map_err(|_| ForkError::Unavailable("fork creation race read"))?;
            job.fence_rows.check(&job, &[authority, epoch])?;
            let raw = raw.ok_or(ForkError::Unavailable(CONTENDED))?;
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
    let mut pending = partitions.as_slice();
    while !pending.is_empty() {
        // Reserve the first existing read before selecting a wave. Inherited
        // layers can debit shared ancestors twice; an opaque leaf needs one
        // more debit. Narrow tight or unknown allowances so a later refusal
        // cannot reclassify an earlier I/O error as a spent fork slice.
        let first_reservation = env.store.reserve_read_calls(1)?;
        let layers = first_reservation
            .as_ref()
            .map_or(0, crate::store::ReadReservation::accounting_layers);
        let debits = layers.saturating_mul(2).saturating_add(1);
        let cap = usize::try_from(env.store.read_call_allowance().unwrap_or(0) / debits)
            .unwrap_or(6)
            .clamp(1, super::WAVE_WIDTH);
        let (wave, rest) = pending.split_at(pending.len().min(cap));
        pending = rest;
        let mut first_reservation = Some(first_reservation);
        let replies = futures::future::join_all(wave.iter().map(|(p, start, end)| {
            let reservation = if let Some(first) = first_reservation.take() {
                Ok(first)
            } else {
                env.store.reserve_read_calls(1)
            };
            async move {
                let reservation = reservation?;
                crate::store::ReadReservation::scope(
                    &[reservation],
                    env.store.scan(p, start, end, None, 1),
                )
                .await
            }
        }))
        .await;
        for reply in replies {
            if !reply?.entries.is_empty() {
                return Err(ForkError::NotEmpty);
            }
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
    #[cfg(feature = "perf-metrics")]
    return super::trace::step(env, dest, budget).await;
    #[cfg(not(feature = "perf-metrics"))]
    step_inner(env, dest, budget).await
}

pub(super) async fn step_inner<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    dest: &RepoId,
    budget: &SliceBudget,
    #[cfg(feature = "perf-metrics")] trace: &super::trace::StepTrace,
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
        let wanted = [
            key.clone(),
            keys::authority_generation(),
            keys::grant_epoch(),
        ];
        let rows = if spent {
            env.store.get_many(&p, &wanted).await?
        } else {
            store.get_many(&p, &wanted).await?
        };
        let (raw, mut job, fence_rows) = decode_progress_rows(rows)?;
        #[cfg(feature = "perf-metrics")]
        trace.note_job(job.phase, job.binding);
        let fence_check = job.fence_rows.check(&job, &fence_rows);
        if job.finished() || (spent && forced.is_none() && fence_check.is_ok()) {
            return Ok(StepReport { job, progressed });
        }
        let before = job.clone();
        let mut outcome = match forced.take() {
            Some(error) => Err(error),
            None => match fence_check {
                Err(error) => Err(error),
                Ok(()) => advance(env, &mut job, budget, &raw, &fence_rows).await,
            },
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
                if before.accepted.is_some()
                    && accepted_progress_changed(env, &before, &raw).await?
                {
                    // Another driver may have completed activation and removed
                    // its barrier while this driver's physical effect lost.
                    continue;
                }
                let failure = terminal_failure(&before, &error)?;
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
        let effects = progress_guards(effects, &before, &job)?;
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
                #[cfg(feature = "perf-metrics")]
                trace.note_committed(job.phase);
                if job.finished() {
                    return Ok(StepReport { job, progressed });
                }
            }
            BatchOutcome::PreconditionFailed { .. } => {
                // Re-read the fence and job together even when the slice was
                // spent. A moved fence terminates an unaccepted attempt;
                // otherwise the next iteration retains ordinary CAS handling.
            }
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(ForkError::Unavailable("fork commit deadline"));
            }
        }
    }
}

/// Retry an accepted clearance refusal only when another driver advanced its job.
/// An unchanged job retains the original refusal after checking the live fence.
async fn accepted_progress_changed<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    raw: &Value,
) -> Result<bool, ForkError> {
    let dest = job.dest()?;
    let rows = env
        .store
        .get_many(
            &env.shards.coordinator(&dest.namespace),
            &[
                keys::fork_job(&dest.name),
                keys::authority_generation(),
                keys::grant_epoch(),
            ],
        )
        .await?;
    let [current, authority, epoch]: [_; 3] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork progress read"))?;
    let current = current.ok_or(ForkError::Unavailable("fork job missing"))?;
    if current != *raw {
        return Ok(true);
    }
    job.fence_rows.check(job, &[authority, epoch])?;
    Ok(false)
}

/// Resolve a physical-effect guard loss against the coordinator snapshot.
/// Reading the job with its fence retains the same CAS-loss observation unit.
pub(super) async fn fence_after_loss<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
) -> Result<(), ForkError> {
    let dest = job.dest()?;
    let rows = env
        .store
        .get_many(
            &env.shards.coordinator(&dest.namespace),
            &[
                keys::fork_job(&dest.name),
                keys::authority_generation(),
                keys::grant_epoch(),
            ],
        )
        .await?;
    let [_, authority, epoch]: [_; 3] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork progress read"))?;
    job.fence_rows.check(job, &[authority, epoch])
}

/// Decode the job and authority facts from one coordinator observation.
fn decode_progress_rows(
    rows: Vec<Option<Value>>,
) -> Result<(Value, ForkJobV1, [Option<Value>; 2]), ForkError> {
    let [raw, authority, epoch]: [_; 3] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork progress read"))?;
    let raw = raw.ok_or(ForkError::Unavailable("fork job missing"))?;
    let job = decode_job(&raw).map_err(|_| ForkError::Unavailable("fork job corrupt"))?;
    Ok((raw, job, [authority, epoch]))
}

/// Acceptance is terminal; a clearance refusal never rewrites its receipt.
fn terminal_failure(job: &ForkJobV1, error: &ForkError) -> Result<Failure, ForkError> {
    if job.accepted.is_some() {
        return Err(match error {
            ForkError::Moved(_) | ForkError::Unavailable(_) => error.clone(),
            _ => ForkError::Unavailable("fork clearance pending"),
        });
    }
    Failure::of(error).ok_or_else(|| error.clone())
}

/// Recorded authority and reservation facts join the existing coordinator CAS.
fn progress_guards(
    mut effects: Batch,
    before: &ForkJobV1,
    job: &ForkJobV1,
) -> Result<Batch, ForkError> {
    if job.phase != Phase::Failed {
        effects.preconditions.extend(job.fence_rows.guards(job));
        if before.accepted.is_none()
            && let Some(settle) = before.settle.as_ref().filter(|s| !s.rid.is_empty())
        {
            let reservation = keys::reservation(&settle.rid)?;
            if !effects
                .preconditions
                .iter()
                .any(|guard| matches!(guard, Precondition::Equals(key, _) if *key == reservation))
            {
                effects.preconditions.push(Precondition::Equals(
                    reservation,
                    Value::new(settle.pending.clone()),
                ));
            }
        }
    }
    Ok(effects)
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

/// Finish accepted clearance after membership installation.
///
/// Proof reclamation changes no decision. Completion still requires the exact
/// accepted inventory before the barrier is removed.
async fn finish_publish<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
    progress: &mkit_primitives::fork::ForkAdvanceFacts,
) -> Result<Batch, ForkError> {
    if job.proof.evidence_pending() && !reclaim_before_clearance(env, &job.dest()?, budget).await? {
        return Ok(Batch::new());
    }
    super::decision::Activation::new(job)?.complete(progress, job)?;
    job.result.clone_from(&job.accepted);
    job.phase = Phase::Done;
    // The walk's scratch sets go; the cleared set and the inherited
    // base packs stay as the boundary.
    let committed = Batch::new()
        .require(Precondition::Equals(
            keys::fork_barrier(&job.dest()?.name),
            Value::new(job.binding.to_vec()),
        ))
        .delete(keys::fork_barrier(&job.dest()?.name));
    Ok(sets::discard(
        committed,
        &job.dest()?.name,
        &[set::TREES, set::QUEUE, set::MANIFESTS],
    ))
}

/// Reclaim transient evidence while retaining the next unit's call reserve.
/// Metadata deletion does not mutate the job or advance a fork decision.
async fn reclaim_before_clearance<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    destination: &RepoId,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    while budget.remaining() >= STEP_RESERVE.saturating_add(3) {
        if super::proof::cleanup(env, destination, budget).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One state's unit of work; returns the coordinator effects to commit with
/// the updated job row.
async fn advance<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
    raw: &Value,
    fence_rows: &[Option<Value>],
) -> Result<Batch, ForkError> {
    let now = env.now();
    if job.accepted.is_none() && now > job.expires_ms {
        return Err(ForkError::Expired);
    }
    let reservation = if job.accepted.is_none() {
        settle::observe(env, job).await?
    } else {
        None
    };
    let progress = super::decision::facts(job, raw, fence_rows, reservation.as_ref())?;
    super::decision::progress(&progress, now)?;
    match job.phase {
        Phase::Plan => {
            if plan::slice(env, job, budget).await? {
                // The charge was an upper bound read at admission: a set that
                // outgrew it is not covered.
                if job.over_admitted() {
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
                // The walk builds the cleared set, which only a deployment
                // with pack-level denial honors: without denial nothing reads
                // it, so no set is built (and a later switch to denial pays a
                // full first walk instead).
                job.phase = if env.takedown_denial {
                    Phase::Walk
                } else {
                    Phase::Register
                };
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
                job.phase = Phase::Accept;
                job.cursor = 0;
                job.part = 0;
                job.after = None;
            }
            Ok(batch)
        }
        Phase::Accept => accept::commit(env, job, budget, now).await,
        Phase::Publish => {
            if job.cursor == 0 {
                // Members are written under guards of their own; a ref that a
                // racing writer created is the one change they cannot see.
                require_empty(env, &job.dest()?, false).await?;
            }
            if !publish::slice(env, job, budget, &progress).await? {
                return Ok(Batch::new());
            }
            finish_publish(env, job, budget, &progress).await
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
    /// Whether pack-level takedown denial is on. Must match the pipeline.
    /// Use [`Self::from_config`] rather than wiring this field independently.
    pub takedown_denial: bool,
    /// The extraction threshold, if extraction is deployed.
    pub extract_min_bytes: Option<u64>,
    /// The same versioned publication policy used by the serving pipeline.
    pub publication_policy:
        Option<std::sync::Arc<dyn crate::pipeline::clearance::PublicationPolicy>>,
}

impl<N> ForkTimer<N> {
    /// Build a timer from the same configuration that serves its destination.
    /// This is the supported construction path; keep that configuration fixed
    /// until all in-flight fork jobs finish before changing denial mode.
    #[must_use]
    pub fn from_config(
        store: N,
        shards: std::sync::Arc<dyn crate::pipeline::ShardMap>,
        clock: std::sync::Arc<dyn crate::rt::Clock>,
        config: &crate::pipeline::PipelineConfig,
    ) -> Self {
        let env = ForkEnv::from_config(&store, shards.as_ref(), clock.as_ref(), config);
        let takedown_denial = env.takedown_denial;
        let extract_min_bytes = env.extract_min_bytes;
        Self {
            store,
            shards,
            clock,
            takedown_denial,
            extract_min_bytes,
            publication_policy: None,
        }
    }

    /// Attach the serving pipeline's coherent publication policy, including
    /// when recovering in-flight work after executor replacement.
    #[must_use]
    pub fn with_publication_policy(
        mut self,
        policy: std::sync::Arc<dyn crate::pipeline::clearance::PublicationPolicy>,
    ) -> Self {
        self.publication_policy = Some(policy);
        self
    }
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
                publication_policy: self.publication_policy.as_deref(),
            };
            let budget = SliceBudget::new(SLICE_CALLS);
            // Clean one page before driving already accepted work, so denial
            // or a moved fence cannot starve transient-metadata reclamation.
            let job_key = keys::fork_job(&dest.name);
            let Some(raw) = ctx.store.get(ctx.partition, &job_key).await? else {
                return Ok(Fired::Done(Batch::new()));
            };
            let initial = decode_job(&raw)?;
            let eligible = initial.accepted.is_some() || initial.finished();
            let mut proof_clean = if eligible && initial.proof.evidence_pending() {
                super::proof::cleanup(&env, &dest, &budget)
                    .await
                    .map_err(|_| StoreError::unavailable("fork source proof cleanup pending"))?
            } else {
                eligible
            };
            let outcome = step(&env, &dest, &budget).await;
            // Acceptance or failure first reached during this tick also starts
            // cleanup, using only the original slice's remaining allowance.
            if !eligible {
                proof_clean = super::proof::cleanup(&env, &dest, &budget)
                    .await
                    .map_err(|_| StoreError::unavailable("fork source proof cleanup pending"))?;
            }
            if initial.phase != Phase::Done
                && matches!(&outcome, Ok(report) if report.job.phase == Phase::Done)
            {
                // Publish now establishes complete evidence cleanup before
                // Done. A false pre-drive page result is no longer current.
                proof_clean = true;
            }
            let retry = |delay| Fired::Reschedule {
                due_at_ms: ctx.now_ms.saturating_add(delay),
                value: Value::default(),
                batch: Batch::new(),
            };
            Ok(match outcome {
                Ok(report) if report.job.finished() && proof_clean => {
                    if report.job.phase == Phase::Done {
                        // Existing permit hygiene shares this same allowance.
                        // Four permit rows cost at most thirteen calls.
                        if budget.remaining() < 20 {
                            return Ok(retry(1_000));
                        }
                        let store = Budgeted::new(env.store, &budget);
                        if !super::permit::release(&env.with_store(&store), &report.job)
                            .await
                            .map_err(|_| StoreError::unavailable("fork permit cleanup pending"))?
                        {
                            return Ok(retry(1_000));
                        }
                    }
                    Fired::Done(Batch::new())
                }
                Ok(_) => retry(1_000),
                Err(_) => retry(crate::timers::RETRY_BACKOFF_MS),
            })
        })
    }
}
