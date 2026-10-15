//! Per-step fork accounting (`perf-metrics` only; see
//! docs/operations/performance-metrics.md).
//!
//! One `fork_step` event per [`super::step`] execution carries the driver
//! (`request` or `alarm`), the phases seen, storage calls split by partition
//! kind, serial rounds, apply and precondition-loss counts, the slice budget
//! spend and the step's wall time. A `fork_step_summary` event on the step
//! whose apply committed the terminal phase sums step executions and
//! precondition losses per driver for the job.
//!
//! All fields are constant labels, counts, durations and a truncated hash of
//! the request binding: no names, keys, values or ids are recorded. The
//! per-job accumulator is removed when the job reaches a terminal phase; a
//! job that never terminates leaves one small map entry.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use mkit_core::hash::{Hash, to_hex_bytes};

use super::{ForkEnv, ForkError, Phase, StepReport};
use crate::RepoId;
use crate::budget::SliceBudget;
use crate::rt::MaybeSend;
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, RangeScan,
    ScanPage, StoreCapabilities, StoreError, Value,
};
use crate::telemetry::slice_context;

/// Partition kinds, in event-field order: the same labels
/// [`Partition::kind`] returns.
const KINDS: [&str; 6] = [
    "namespace",
    "coordinator",
    "ref",
    "repo_index",
    "ref_index",
    "content",
];

fn kind_index(kind: &str) -> usize {
    KINDS
        .iter()
        .position(|k| *k == kind)
        .expect("Partition::kind stays inside KINDS")
}

/// The counters one step execution fills. Shared with the [`Traced`] store
/// through atomics so concurrent partition waves count correctly.
pub(super) struct StepTrace {
    calls: [AtomicU64; KINDS.len()],
    /// Calls that started while nothing else was in flight: the count of
    /// serial round trips this step paid.
    serial_rounds: AtomicU64,
    in_flight: AtomicU64,
    applies: AtomicU64,
    /// Applies lost to `PreconditionFailed` (another driver wrote first).
    cas_losses: AtomicU64,
    /// The phase and request binding of the first job row the step read;
    /// errored steps still attribute when a row decoded.
    seen: Mutex<Option<(Phase, Hash)>>,
    /// The phase the step's last committed apply produced. A step that lost
    /// the job-row CAS and re-read the winner's `Done` row did not commit it
    /// and emits no summary — only the committer does.
    committed: Mutex<Option<Phase>>,
}

impl StepTrace {
    fn new() -> Self {
        Self {
            calls: Default::default(),
            serial_rounds: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            applies: AtomicU64::new(0),
            cas_losses: AtomicU64::new(0),
            seen: Mutex::new(None),
            committed: Mutex::new(None),
        }
    }

    /// One backend call started on `kind`; the returned guard ends it.
    fn call(&self, kind: &str) -> InFlight<'_> {
        self.calls[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
        if self.in_flight.fetch_add(1, Ordering::Relaxed) == 0 {
            self.serial_rounds.fetch_add(1, Ordering::Relaxed);
        }
        InFlight(self)
    }

    fn apply_done(&self, outcome: &Result<BatchOutcome, StoreError>) {
        self.applies.fetch_add(1, Ordering::Relaxed);
        if matches!(outcome, Ok(BatchOutcome::PreconditionFailed { .. })) {
            self.cas_losses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `job.phase` and `job.binding` at the step's first row read; later
    /// re-reads do not move it.
    pub(super) fn note_job(&self, phase: Phase, binding: Hash) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert((phase, binding));
    }

    /// The phase of the job row this step just committed; only a commit can
    /// own a terminal transition.
    pub(super) fn note_committed(&self, phase: Phase) {
        *self
            .committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(phase);
    }

    fn calls(&self) -> [u64; KINDS.len()] {
        std::array::from_fn(|i| self.calls[i].load(Ordering::Relaxed))
    }
}

struct InFlight<'a>(&'a StepTrace);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The [`NamespaceStore`] one traced step sees: every call counts once against
/// its partition kind; bookkeeping and activation hints delegate uncounted.
struct Traced<'a, S> {
    inner: &'a S,
    stats: &'a StepTrace,
}

impl<S: NamespaceStore> NamespaceStore for Traced<'_, S> {
    fn prepare_repo_read(&self, repo: &RepoId) -> impl Future<Output = ()> + MaybeSend {
        self.inner.prepare_repo_read(repo)
    }

    fn prepare_anonymous_repo_read(&self, repo: &RepoId) -> impl Future<Output = ()> + MaybeSend {
        self.inner.prepare_anonymous_repo_read(repo)
    }

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn reader_admission(&self) -> bool {
        self.inner.reader_admission()
    }

    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }

    fn reserve_read_calls(
        &self,
        calls: u32,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        self.inner.reserve_read_calls(calls)
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.get(p, key).await
    }

    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.has(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.get_many(p, keys).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.scan_many(p, ranges).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let _call = self.stats.call(p.kind());
        let outcome = self.inner.apply(p, batch).await;
        self.stats.apply_done(&outcome);
        outcome
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        let _call = self.stats.call(p.kind());
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        let _call = self.stats.call("namespace");
        self.inner.probe().await
    }
}

fn phase_name(phase: Option<Phase>) -> &'static str {
    match phase {
        Some(Phase::Plan) => "plan",
        Some(Phase::Trees) => "trees",
        Some(Phase::Walk) => "walk",
        Some(Phase::Register) => "register",
        Some(Phase::Copy) => "copy",
        Some(Phase::Count) => "count",
        Some(Phase::Publish) => "publish",
        Some(Phase::Done) => "done",
        Some(Phase::Failed) => "failed",
        None => "absent",
    }
}

/// Per-job roll-up, keyed by the request binding.
#[derive(Default)]
struct PerJob {
    request_steps: u64,
    alarm_steps: u64,
    cas_losses: u64,
}

static JOBS: Mutex<BTreeMap<Hash, PerJob>> = Mutex::new(BTreeMap::new());

/// `super::job::step` under measurement: the store is wrapped, the run is
/// timed, and one `fork_step` event is emitted with what the execution spent.
pub(super) async fn step<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    dest: &RepoId,
    budget: &SliceBudget,
) -> Result<StepReport, ForkError> {
    let trace = StepTrace::new();
    let traced = Traced {
        inner: env.store,
        stats: &trace,
    };
    let env = ForkEnv {
        store: &traced,
        shards: env.shards,
        clock: env.clock,
        takedown_denial: env.takedown_denial,
        extract_min_bytes: env.extract_min_bytes,
        limits: env.limits,
    };
    let timer = slice_context::timer();
    let started_ms = env.now();
    let calls_before = budget.used();
    let result = super::job::step_inner(&env, dest, budget, &trace).await;
    let wall_ms = env.now().saturating_sub(started_ms);

    let driver = if timer.is_some() { "alarm" } else { "request" };
    let report = result.as_ref().ok();
    let seen = *trace.seen.lock().unwrap_or_else(PoisonError::into_inner);
    let phase_in = seen.map(|(phase, _)| phase);
    let binding = report
        .map(|report| report.job.binding)
        .or(seen.map(|(_, b)| b));
    let job = binding.map(|binding| to_hex_bytes(&binding[..8]));
    let calls = trace.calls();
    let cas_losses = trace.cas_losses.load(Ordering::Relaxed);
    let error = result.as_ref().err().map(|error| match error {
        ForkError::Slice => "slice",
        ForkError::Unavailable(_) => "unavailable",
        ForkError::Expired => "expired",
        ForkError::NotFound => "not_found",
        ForkError::TipChanged => "tip_changed",
        ForkError::TooLarge => "too_large",
        ForkError::NotEmpty => "not_empty",
        ForkError::Denied => "denied",
        ForkError::Moved(_) => "moved",
        ForkError::Quota(_) => "quota",
    });
    tracing::info!(
        event = "fork_step",
        driver,
        job = job.as_deref().unwrap_or("-"),
        phase_in = phase_name(phase_in),
        // The exit phase is observed only through a returned report; an
        // errored step reports "-" rather than claiming `absent`.
        phase_out = report.map_or("-", |report| phase_name(Some(report.job.phase))),
        wall_ms,
        calls = calls.iter().sum::<u64>(),
        calls_coordinator = calls[kind_index("coordinator")],
        calls_content = calls[kind_index("content")],
        calls_ref = calls[kind_index("ref")],
        calls_repo_index = calls[kind_index("repo_index")],
        calls_ref_index = calls[kind_index("ref_index")],
        calls_namespace = calls[kind_index("namespace")],
        serial_rounds = trace.serial_rounds.load(Ordering::Relaxed),
        applies = trace.applies.load(Ordering::Relaxed),
        cas_losses,
        budget_calls = budget.used().saturating_sub(calls_before),
        progressed = report.is_some_and(|report| report.progressed),
        finished = report.is_some_and(|report| report.job.finished()),
        error = error.unwrap_or("none"),
        // Absent on request rows: zero is a measurement, not unavailable
        // evidence.
        timer_scheduled_ms = timer.map(|timer| timer.scheduled_ms),
        logical_due_ms = timer.map(|timer| timer.logical_due_ms),
        timer_retry_attempt = timer.map(|timer| u64::from(timer.retry_attempt)),
        timer_delay_ms = timer.map(|timer| started_ms.saturating_sub(timer.scheduled_ms)),
    );
    if let Some(binding) = binding {
        let mut jobs = JOBS.lock().unwrap_or_else(PoisonError::into_inner);
        let mut per_job = jobs.remove(&binding).unwrap_or_default();
        match driver {
            "alarm" => per_job.alarm_steps += 1,
            _ => per_job.request_steps += 1,
        }
        per_job.cas_losses += cas_losses;
        // The summary belongs to the step whose apply committed the job's
        // terminal phase. A stale timer or a CAS loser that re-read the
        // winner's `Done`/`Failed` row emits its `fork_step` row but no
        // second summary; its counts stay merged so the committer's summary
        // still includes them. The first step that *entered* on a terminal
        // row drops the entry — the guaranteed stale fire after `Done`
        // bounds the accumulator.
        let finished = report.is_some_and(|report| report.job.finished());
        let entered_terminal = matches!(phase_in, Some(Phase::Done | Phase::Failed));
        let committed = *trace
            .committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if finished && committed == report.map(|report| report.job.phase) {
            tracing::info!(
                event = "fork_step_summary",
                job = %to_hex_bytes(&binding[..8]),
                request_steps = per_job.request_steps,
                alarm_steps = per_job.alarm_steps,
                cas_losses = per_job.cas_losses,
            );
        } else if !entered_terminal {
            jobs.insert(binding, per_job);
        }
    }
    result
}
