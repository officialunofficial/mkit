//! Partition-local timers, shared by native and Durable Object drivers.

mod budget;
pub use budget::TickState;

pub mod lease_sweep;
pub mod outcome_delivery;
pub mod publication_recheck;
pub mod quota_rollup;
pub mod registry;
pub mod reservation_reconcile;
#[cfg(feature = "test-faults")]
pub mod test_kind;
#[cfg(test)]
mod tests;
pub mod ticket_expiry;

use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
    keys,
};
use bytes::Bytes;
pub use registry::{TimerHandler, TimerKind, TimerRegistry};

/// Delay before retrying failed or unknown timers, avoiding a busy loop.
pub const RETRY_BACKOFF_MS: u64 = 5_000;
/// Largest persisted retry delay, including after an isolate restart.
pub const MAX_RETRY_BACKOFF_MS: u64 = 600_000;
const PAGE_SIZE: u32 = 64;

/// The row handed to a kind-specific codec and handler.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DueTimer {
    /// Scheduled Unix epoch milliseconds.
    pub due_at_ms: u64,
    /// Stable handler identifier.
    pub kind: TimerKind,
    /// Opaque kind-specific identity.
    pub reference: Bytes,
    /// Opaque kind-specific payload.
    pub value: Value,
}
/// Reads available to a handler; effects belong in the returned batch.
#[non_exhaustive]
#[derive(Debug)]
pub struct TimerCtx<'a, S> {
    /// The driver's concrete store.
    pub store: &'a S,
    /// Atomicity boundary for every returned effect.
    pub partition: &'a Partition,
    /// Business time for this tick.
    pub now_ms: u64,
}
/// A handler's decision, committed by the core.
#[non_exhaustive]
#[derive(Debug)]
pub enum Fired {
    /// Commit `batch` and delete the timer, atomically.
    Done(Batch),
    /// Commit effects and move the timer atomically.
    Reschedule {
        /// New Unix epoch milliseconds; must change the timer key.
        due_at_ms: u64,
        /// New kind-specific payload.
        value: Value,
        /// Effects in this partition.
        batch: Batch,
    },
    /// No effect now; try again later (counts as a failure for backoff).
    Retry,
}
/// Work limits shared by every logical partition of one physical tick.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct TickBudget {
    /// Maximum successful commits.
    pub max_fired: u32,
    /// Maximum handler invocations per kind, including failed attempts.
    pub max_per_kind: u32,
    /// Maximum examined rows, including unknown and deferred kinds.
    pub max_scanned: u32,
    /// Maximum elapsed injected-clock milliseconds.
    pub max_elapsed_ms: u64,
}
impl TickBudget {
    /// Construct limits, clamping each to at least one.
    #[must_use]
    pub const fn new(
        max_fired: u32,
        max_per_kind: u32,
        max_scanned: u32,
        max_elapsed_ms: u64,
    ) -> Self {
        Self {
            max_fired: if max_fired == 0 { 1 } else { max_fired },
            max_per_kind: if max_per_kind == 0 { 1 } else { max_per_kind },
            max_scanned: if max_scanned == 0 { 1 } else { max_scanned },
            max_elapsed_ms: if max_elapsed_ms == 0 {
                1
            } else {
                max_elapsed_ms
            },
        }
    }
}
impl Default for TickBudget {
    fn default() -> Self {
        Self::new(128, 32, 512, 10_000)
    }
}
/// Counts and the next driver wake, never earlier than this tick's business time.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunReport {
    /// Successfully committed timer batches.
    pub fired: u32,
    /// Batches lost to a precondition race.
    pub raced: u32,
    /// Handler or commit failures.
    pub failed: u32,
    /// Rows owned by unregistered kinds.
    pub unknown: u32,
    /// Rows skipped by a kind's invocation cap.
    pub deferred: u32,
    /// Examined due rows.
    pub scanned: u32,
    /// A global work limit stopped the tick.
    pub stopped_on_budget: bool,
    /// Next scheduled wake for this partition.
    pub next_wake_ms: Option<u64>,
}

/// Earliest timer Put in a batch, shared by both driver adapters.
#[must_use]
pub fn earliest_timer_put(batch: &Batch) -> Option<u64> {
    batch
        .writes
        .iter()
        .filter_map(|write| match write {
            Write::Put(key, _) => match keys::parse(key) {
                Some(keys::ParsedKey::Timer { due_at_ms, .. }) => Some(due_at_ms),
                _ => None,
            },
            Write::Delete(_) => None,
        })
        .min()
}
fn min_due(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn time_prefix(now: u64) -> Key {
    Key::new([&b"w\0"[..], &now.to_be_bytes()].concat())
}
enum FireOutcome {
    Committed(Option<u64>),
    Raced,
    Failed,
}

async fn fire_timer<S: NamespaceStore>(
    handler: &dyn TimerHandler<S>,
    ctx: &TimerCtx<'_, S>,
    timer: &DueTimer,
    key: Key,
) -> FireOutcome {
    let batch = match handler.fire(ctx, timer).await {
        Ok(Fired::Done(batch)) => batch
            .require(Precondition::Equals(key.clone(), timer.value.clone()))
            .delete(key),
        Ok(Fired::Reschedule {
            due_at_ms,
            value,
            batch,
        }) => {
            let new_key = keys::timer(due_at_ms, timer.kind.get(), &timer.reference);
            if due_at_ms == timer.due_at_ms || new_key == key {
                return FireOutcome::Failed;
            }
            batch
                .require(Precondition::Equals(key.clone(), timer.value.clone()))
                .require(Precondition::Absent(new_key.clone()))
                .delete(key)
                .put(new_key, value)
        }
        Ok(Fired::Retry) => {
            #[cfg(feature = "test-faults")]
            tracing::warn!(kind = timer.kind.get(), "test timer requested retry");
            return FireOutcome::Failed;
        }
        Err(error) => {
            #[cfg(feature = "test-faults")]
            tracing::warn!(kind = timer.kind.get(), %error, "test timer handler failed");
            #[cfg(not(feature = "test-faults"))]
            let _ = error;
            return FireOutcome::Failed;
        }
    };
    let put_due = earliest_timer_put(&batch);
    match ctx.store.apply(ctx.partition, batch).await {
        Ok(BatchOutcome::Committed) => FireOutcome::Committed(put_due),
        Ok(BatchOutcome::PreconditionFailed { .. }) => FireOutcome::Raced,
        Ok(BatchOutcome::DeadlinePassed { .. }) => {
            #[cfg(feature = "test-faults")]
            tracing::warn!(kind = timer.kind.get(), "test timer deadline passed");
            FireOutcome::Failed
        }
        Err(error) => {
            #[cfg(feature = "test-faults")]
            tracing::warn!(kind = timer.kind.get(), %error, "test timer apply failed");
            #[cfg(not(feature = "test-faults"))]
            let _ = error;
            FireOutcome::Failed
        }
    }
}

/// Fire one partition with its own allowance. Physical drivers should use
/// [`run_due_with_state`] and share a single [`TickState`] across their heads.
///
/// # Errors
/// Scan errors escape. Handler/apply failures remain durable timer work.
pub async fn run_due<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    registry: &TimerRegistry<'_, S>,
    clock: &dyn Clock,
    now_ms: u64,
    budget: &TickBudget,
) -> Result<RunReport, StoreError> {
    let mut state = TickState::new(clock, *budget);
    run_due_with_state(store, p, registry, clock, now_ms, &mut state).await
}

/// Fire a partition without refreshing physical-alarm limits. Scans reserve
/// their returned rows and one portable SQL lookahead row before processing.
/// Retry moves preserve the handler's original due time and opaque payload.
///
/// # Errors
/// Only scan errors escape; failed retry moves retain the guarded original row.
pub async fn run_due_with_state<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    registry: &TimerRegistry<'_, S>,
    clock: &dyn Clock,
    now_ms: u64,
    state: &mut TickState,
) -> Result<RunReport, StoreError> {
    let (start, class_end) = keys::class_range(keys::TAG_TIMER);
    let end = now_ms
        .checked_add(1)
        .map_or_else(|| class_end.clone(), time_prefix);
    let ctx = TimerCtx {
        store,
        partition: p,
        now_ms,
    };
    let mut run = PartitionRun::new();
    let mut cursor = None;
    'pages: loop {
        if state.exhausted(clock) || state.remaining_scanned() < 2 {
            run.report.stopped_on_budget = true;
            break;
        }
        let limit = PAGE_SIZE.min(state.remaining_scanned() - 1);
        let page = store.scan(p, &start, &end, cursor.as_ref(), limit).await?;
        // SQL scans use LIMIT limit+1. Charge conservatively on other backends.
        let rows = u32::try_from(page.entries.len()).unwrap_or(limit);
        let _ = state.charge_scan(rows + 1);
        for (key, value) in page.entries {
            if state.work_exhausted(clock) {
                run.report.stopped_on_budget = true;
                break 'pages;
            }
            run.report.scanned += 1;
            process_row(&ctx, registry, key, value, state, &mut run).await;
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    // If the future range cannot be examined, keep a wake even when the
    // final due page happened to end exactly at the commit/clock allowance.
    if now_ms < u64::MAX && (state.work_exhausted(clock) || state.remaining_scanned() < 2) {
        run.report.stopped_on_budget = true;
    }
    let future_due =
        if !state.work_exhausted(clock) && state.remaining_scanned() >= 2 && now_ms < u64::MAX {
            let page = store.scan(p, &end, &class_end, None, 1).await?;
            let _ = state.charge_scan(2);
            page.entries
                .first()
                .and_then(|(key, _)| match keys::parse(key) {
                    Some(keys::ParsedKey::Timer { due_at_ms, .. }) => Some(due_at_ms),
                    _ => None,
                })
        } else {
            None
        };
    let pending = run.report.stopped_on_budget || run.retained_due;
    let next = if pending && run.progress {
        Some(now_ms)
    } else if pending {
        Some(now_ms.saturating_add(RETRY_BACKOFF_MS))
    } else {
        future_due
    };
    run.report.next_wake_ms =
        min_due(min_due(next, future_due), run.committed_due).map(|due| due.max(now_ms));
    Ok(run.report)
}

struct PartitionRun {
    report: RunReport,
    warned: [bool; 256],
    retained_due: bool,
    committed_due: Option<u64>,
    progress: bool,
}
impl PartitionRun {
    fn new() -> Self {
        Self {
            report: RunReport::default(),
            warned: [false; 256],
            retained_due: false,
            committed_due: None,
            progress: false,
        }
    }
}

async fn process_row<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    registry: &TimerRegistry<'_, S>,
    key: Key,
    value: Value,
    state: &mut TickState,
    run: &mut PartitionRun,
) {
    let Some(keys::ParsedKey::Timer {
        kind, reference, ..
    }) = keys::parse(&key)
    else {
        // Corrupt encodings cannot safely be moved; retain them for repair.
        run.report.unknown += 1;
        run.retained_due = true;
        if !run.warned[0] {
            tracing::warn!("malformed timer row");
            run.warned[0] = true;
        }
        return;
    };
    let Some((original_due, attempt)) = keys::timer_retry_state(&key) else {
        run.retained_due = true;
        return;
    };
    let timer = DueTimer {
        due_at_ms: original_due,
        kind: TimerKind::new(kind),
        reference,
        value,
    };
    let Some(handler) = registry.get(timer.kind) else {
        run.report.unknown += 1;
        if !run.warned[usize::from(kind)] {
            tracing::warn!(kind, "unknown timer kind");
            run.warned[usize::from(kind)] = true;
        }
        match backoff(ctx, &timer, key, attempt).await {
            FireOutcome::Committed(due) => {
                state.committed();
                run.progress = true;
                run.committed_due = min_due(run.committed_due, due);
            }
            FireOutcome::Raced => {
                run.report.raced += 1;
                run.retained_due = true;
            }
            FireOutcome::Failed => {
                run.report.failed += 1;
                run.retained_due = true;
            }
        }
        return;
    };
    if !state.claim_attempt(timer.kind, handler.max_per_tick()) {
        run.report.deferred += 1;
        run.retained_due = true;
        return;
    }
    match fire_timer(handler, ctx, &timer, key.clone()).await {
        FireOutcome::Committed(put_due) => {
            state.committed();
            run.report.fired += 1;
            run.progress = true;
            run.committed_due = min_due(run.committed_due, put_due);
        }
        FireOutcome::Raced => {
            run.report.raced += 1;
            run.retained_due = true;
        }
        FireOutcome::Failed => {
            run.report.failed += 1;
            // Failed handler effects are discarded; only its timer moves.
            match backoff(ctx, &timer, key, attempt).await {
                FireOutcome::Committed(due) => {
                    state.committed();
                    run.progress = true;
                    run.committed_due = min_due(run.committed_due, due);
                }
                FireOutcome::Raced => {
                    run.report.raced += 1;
                    run.retained_due = true;
                }
                FireOutcome::Failed => run.retained_due = true,
            }
        }
    }
}

async fn backoff<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    timer: &DueTimer,
    key: Key,
    attempt: u8,
) -> FireOutcome {
    let next_attempt = attempt.saturating_add(1).min(keys::MAX_TIMER_RETRY_ATTEMPT);
    let delay = RETRY_BACKOFF_MS
        .saturating_mul(1_u64 << (next_attempt - 1))
        .min(MAX_RETRY_BACKOFF_MS);
    let due = ctx.now_ms.saturating_add(delay);
    let next_key = keys::timer_retry(
        due,
        timer.kind.get(),
        &timer.reference,
        timer.due_at_ms,
        next_attempt,
    );
    if next_key == key {
        return FireOutcome::Failed;
    }
    let batch = Batch::new()
        .require(Precondition::Equals(key.clone(), timer.value.clone()))
        .require(Precondition::Absent(next_key.clone()))
        .delete(key)
        .put(next_key, timer.value.clone());
    match ctx.store.apply(ctx.partition, batch).await {
        Ok(BatchOutcome::Committed) => FireOutcome::Committed(Some(due)),
        Ok(BatchOutcome::PreconditionFailed { .. }) => FireOutcome::Raced,
        Ok(BatchOutcome::DeadlinePassed { .. }) | Err(_) => FireOutcome::Failed,
    }
}
