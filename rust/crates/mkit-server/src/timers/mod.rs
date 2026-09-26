//! Partition-local timers, shared by native and Durable Object drivers.

pub mod registry;
#[cfg(feature = "test-faults")]
pub mod test_kind;
#[cfg(test)]
mod tests;

use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
    keys,
};
use bytes::Bytes;
pub use registry::{TimerHandler, TimerKind, TimerRegistry};

/// Delay before retrying failed or unknown timers, avoiding a busy loop.
pub const RETRY_BACKOFF_MS: u64 = 5_000;
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
/// Work limits for one partition tick.
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
fn exhausted(report: &RunReport, clock: &dyn Clock, start: i64, budget: &TickBudget) -> bool {
    report.fired >= budget.max_fired
        || report.scanned >= budget.max_scanned
        || u64::try_from(clock.now_ms().saturating_sub(start)).unwrap_or(0) >= budget.max_elapsed_ms
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
            if new_key == key {
                return FireOutcome::Failed;
            }
            batch
                .require(Precondition::Equals(key.clone(), timer.value.clone()))
                .delete(key)
                .put(new_key, value)
        }
        Ok(Fired::Retry) | Err(_) => return FireOutcome::Failed,
    };
    let put_due = earliest_timer_put(&batch);
    match ctx.store.apply(ctx.partition, batch).await {
        Ok(BatchOutcome::Committed) => FireOutcome::Committed(put_due),
        Ok(BatchOutcome::PreconditionFailed { .. }) => FireOutcome::Raced,
        Ok(BatchOutcome::DeadlinePassed { .. }) | Err(_) => FireOutcome::Failed,
    }
}

/// Fire due rows in key order, with fair kind caps and atomic row-value guards.
///
/// # Errors
/// Only a failed scan escapes the tick. Handler and apply errors count as failures.
pub async fn run_due<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    registry: &TimerRegistry<S>,
    clock: &dyn Clock,
    now_ms: u64,
    budget: &TickBudget,
) -> Result<RunReport, StoreError> {
    let start_time = clock.now_ms();
    let (start, class_end) = keys::class_range(keys::TAG_TIMER);
    let end = now_ms
        .checked_add(1)
        .map_or_else(|| class_end.clone(), time_prefix);
    let ctx = TimerCtx {
        store,
        partition: p,
        now_ms,
    };
    let mut report = RunReport::default();
    let mut per_kind = [0u32; 256];
    let mut warned = [false; 256];
    let mut cursor = None;
    let mut committed_due = None;
    'pages: loop {
        if exhausted(&report, clock, start_time, budget) {
            report.stopped_on_budget = true;
            break;
        }
        let page = store
            .scan(
                p,
                &start,
                &end,
                cursor.as_ref(),
                PAGE_SIZE.min(budget.max_scanned - report.scanned),
            )
            .await?;
        for (key, value) in page.entries {
            if exhausted(&report, clock, start_time, budget) {
                report.stopped_on_budget = true;
                break 'pages;
            }
            report.scanned += 1;
            let Some(keys::ParsedKey::Timer {
                due_at_ms,
                kind,
                reference,
            }) = keys::parse(&key)
            else {
                // Malformed rows are retained, like an unknown codec, for repair.
                report.unknown += 1;
                if !warned[0] {
                    tracing::warn!("malformed timer row");
                    warned[0] = true;
                }
                continue;
            };
            let timer = DueTimer {
                due_at_ms,
                kind: TimerKind::new(kind),
                reference,
                value,
            };
            let Some(handler) = registry.get(timer.kind) else {
                report.unknown += 1;
                if !warned[usize::from(kind)] {
                    tracing::warn!(kind, "unknown timer kind");
                    warned[usize::from(kind)] = true;
                }
                continue;
            };
            let count = &mut per_kind[usize::from(kind)];
            if *count >= handler.max_per_tick().unwrap_or(budget.max_per_kind) {
                report.deferred += 1;
                continue;
            }
            *count += 1;
            match fire_timer(handler, &ctx, &timer, key).await {
                FireOutcome::Committed(put_due) => {
                    report.fired += 1;
                    committed_due = min_due(committed_due, put_due);
                }
                FireOutcome::Raced => report.raced += 1,
                FireOutcome::Failed => report.failed += 1,
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    let future_due = if !report.stopped_on_budget && now_ms < u64::MAX {
        store
            .scan(p, &end, &class_end, None, 1)
            .await?
            .entries
            .first()
            .and_then(|(key, _)| match keys::parse(key) {
                Some(keys::ParsedKey::Timer { due_at_ms, .. }) => Some(due_at_ms),
                _ => None,
            })
    } else {
        None
    };
    report.next_wake_ms = next_wake(&report, now_ms, future_due, committed_due);
    Ok(report)
}

fn next_wake(
    report: &RunReport,
    now_ms: u64,
    future_due: Option<u64>,
    committed_due: Option<u64>,
) -> Option<u64> {
    let next = if (report.stopped_on_budget || report.deferred > 0) && report.fired > 0 {
        Some(now_ms)
    } else if report.failed > 0 || report.unknown > 0 || report.stopped_on_budget {
        min_due(future_due, Some(now_ms.saturating_add(RETRY_BACKOFF_MS)))
    } else {
        future_due
    };
    min_due(next, committed_due).map(|due| due.max(now_ms))
}
