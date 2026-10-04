//! Ordered target batches, guarded watermarks, and bounded source cleanup.

use std::collections::BTreeSet;

use super::{NoHook, RELAY_LAG_BOUND_MS, RelayBudget, RelayHook};
use crate::rt::BoxFuture;
use crate::store::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreCapabilities,
    StoreError, Value, Write,
    codec::{self, MAX_BLOCKED_TARGETS, RelayScanV1, RelayV1},
    keys, repo_storage,
};
use crate::telemetry::{
    METRIC_RELAY_BACKLOG_ROWS, METRIC_RELAY_LAG_EXCEEDED, METRIC_RELAY_STORAGE_COUNTER_MISSING,
    Metrics, NoopMetrics,
};
use crate::timers::{
    DueTimer, Fired, RETRY_BACKOFF_MS, TimerCtx, TimerHandler, TimerKind, registry::kinds,
};

// Keep encoded pages and decoded groups comfortably below a Worker isolate's
// 128 MiB limit, even when rows approach MAX_VALUE_BYTES. The row/target budget
// remains an upper bound; leftover rows schedule another tick.
const MAX_FIRE_BYTES: usize = 4 * 1024 * 1024;
const SCAN_PAGE_ROWS: u32 = 64;
// At most 6 MiB raw snapshot values even for corrupt maximum-sized rows.
// Together with source pages and JSON/JS copies this leaves hook headroom.
// Twelve fit the watermark, the outbox rows and the counter-marker rows
// of a seven-pack advance (`repo_storage`).
const MAX_HOOK_READ_KEYS: usize = 12;
// The watermark, the outbox sequence and backlog, the counter and one marker
// per counted pack of a single relay row must fit: otherwise a coordinator
// target would stall permanently.
const _: () = assert!(4 + repo_storage::MAX_COUNTED_PACKS <= MAX_HOOK_READ_KEYS);

type QueuedRow = (u64, RelayV1, Key, Value);
type TargetRows = (Partition, Vec<QueuedRow>);
type InspectedRow = (u64, Partition, Key, Value);

struct ScanWindow {
    rows: Vec<InspectedRow>,
    groups: Vec<TargetRows>,
    corrupt: bool,
    exhausted: bool,
    lag_exceeded: bool,
}

struct Dispatch {
    delivered: BTreeSet<u64>,
    block: BTreeSet<Partition>,
    pause_at: Option<u64>,
    overflow_at: Option<u64>,
}

struct TargetResult {
    completed: usize,
    failed: bool,
    selected: bool,
    calls: u32,
}

/// Pushes a source's queued rows to a separately supplied target store.
/// Distinct producers may upsert the same key when its value is identical.
/// A key that is ever relay-deleted MUST have exactly one producer, so its
/// source sequence orders every update and delete.
/// Target rh rows never expire.
#[derive(Debug)]
pub struct RelayHandler<T, H = NoHook> {
    /// Target store (may be a clone of the source store on native).
    pub target: T,
    /// Atomic target-batch extension.
    pub hook: H,
    /// Per-fire work cap.
    pub budget: RelayBudget,
}

impl<S: NamespaceStore, T: NamespaceStore, H: RelayHook> TimerHandler<S> for RelayHandler<T, H> {
    fn kind(&self) -> TimerKind {
        kinds::RELAY
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(self.deliver_with_metrics(ctx, timer, &NoopMetrics))
    }
}

#[cfg(feature = "__test-faults")]
async fn apply_relay_delay<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    timer: &DueTimer,
) -> Result<Option<Fired>, StoreError> {
    let marker = crate::pipeline::faults::relay_delay_key();
    let Some(value) = ctx.store.get(ctx.partition, &marker).await? else {
        return Ok(None);
    };
    let until = codec::decode_u64(&value)?;
    if ctx.now_ms < until {
        return Ok(Some(Fired::Reschedule {
            due_at_ms: until.max(timer.due_at_ms.saturating_add(1)),
            value: timer.value.clone(),
            batch: Batch::new(),
        }));
    }
    Ok(
        match ctx
            .store
            .apply(
                ctx.partition,
                Batch::new()
                    .require(Precondition::Equals(marker.clone(), value))
                    .delete(marker),
            )
            .await?
        {
            BatchOutcome::Committed => None,
            BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => {
                Some(Fired::Retry)
            }
        },
    )
}

impl<T: NamespaceStore, H: RelayHook> RelayHandler<T, H> {
    /// Deliver one relay fire while recording source backlog and lag.
    pub async fn deliver_with_metrics<S: NamespaceStore>(
        &self,
        ctx: &TimerCtx<'_, S>,
        timer: &DueTimer,
        metrics: &dyn Metrics,
    ) -> Result<Fired, StoreError> {
        #[cfg(feature = "__test-faults")]
        if let Some(fired) = apply_relay_delay(ctx, timer).await? {
            return Ok(fired);
        }
        let os_key = keys::outbox_sequence();
        let sequence_value = ctx.store.get(ctx.partition, &os_key).await?;
        let os = sequence_value
            .as_ref()
            .map(codec::decode_u64)
            .transpose()?
            .unwrap_or(0);
        let rs_key = keys::relay_scan();
        let mut scan_value = ctx.store.get(ctx.partition, &rs_key).await?;
        let mut scan = scan_value
            .as_ref()
            .and_then(|value| match codec::decode_relay_scan(value) {
                Ok(state) => Some(state),
                Err(error) => {
                    tracing::warn!(
                        source = ?ctx.partition,
                        %error,
                        "corrupt relay scan state; restarting from source head"
                    );
                    None
                }
            })
            .filter(|state| state.cursor < state.cycle_end)
            .unwrap_or(RelayScanV1 {
                cycle_end: os,
                cursor: 0,
                blocked: Vec::new(),
            });
        let max_rows = self.budget.max_rows.max(1);
        let (rows, exhausted) = read_rows(ctx, &scan, max_rows.saturating_mul(4)).await?;
        let window = decode_window(ctx.partition, ctx.now_ms, rows, exhausted);
        // `os - first_queued_seq + 1` is an upper bound: out-of-order
        // delivered rows may leave holes, but a bounded scan window must
        // never hide a large queued tail from the backlog gauge.
        let (start, end) = keys::class_range(keys::TAG_RELAY);
        let head = ctx.store.scan(ctx.partition, &start, &end, None, 1).await?;
        let backlog = match head.entries.first().and_then(|(key, _)| keys::parse(key)) {
            Some(keys::ParsedKey::Relay(first)) => os.saturating_sub(first).saturating_add(1),
            _ => 0,
        };
        #[allow(clippy::cast_precision_loss)]
        metrics.gauge(
            METRIC_RELAY_BACKLOG_ROWS,
            &[("source_kind", source_kind(ctx.partition))],
            backlog as f64,
        );
        if window.lag_exceeded {
            metrics.incr(
                METRIC_RELAY_LAG_EXCEEDED,
                &[("source_kind", source_kind(ctx.partition))],
                1,
            );
        }
        let rh = keys::relay_high_water(ctx.partition)?;
        let dispatch = self
            .dispatch(&window.groups, &scan.blocked, &rh, metrics)
            .await;
        if !checkpoint_window(ctx, &rs_key, &mut scan_value, &mut scan, &window, &dispatch).await? {
            return Ok(Fired::Retry);
        }
        if window.corrupt {
            // The valid prefix is durable; the malformed row stays at the
            // front of the next scan and is never bypassed.
            return Ok(Fired::Retry);
        }
        let has_remaining = if !scan.blocked.is_empty()
            || scan.cursor < scan.cycle_end
            || window.rows.len() > dispatch.delivered.len()
        {
            true
        } else {
            let remaining = ctx.store.scan(ctx.partition, &start, &end, None, 1).await?;
            !remaining.entries.is_empty() || remaining.next.is_some()
        };
        // Target watermarks are durable and source cleanup has committed.
        // The remaining source head gives a conservative contiguous watermark.
        let nudged = !dispatch.delivered.is_empty()
            && crate::indexed::wake::after_relay(ctx, os, metrics).await;
        // A nudge can insert behind the timer driver's current scan cursor.
        // Keep a prompt relay continuation so that the next tick discovers it.
        if has_remaining || nudged {
            let due = ctx
                .now_ms
                .saturating_add(if dispatch.delivered.is_empty() {
                    RETRY_BACKOFF_MS
                } else {
                    1
                })
                .max(timer.due_at_ms.saturating_add(1));
            Ok(Fired::Reschedule {
                due_at_ms: due,
                value: Value::default(),
                batch: Batch::new(),
            })
        } else {
            // Guard `os` either way: a first-ever relay row committed during
            // this fire moves `os` from absent, so `Done` races and the timer
            // stays.
            Ok(Fired::Done(Batch::new().require(match sequence_value {
                Some(value) => Precondition::Equals(os_key, value),
                None => Precondition::Absent(os_key),
            })))
        }
    }

    async fn dispatch(
        &self,
        groups: &[TargetRows],
        blocked: &[Partition],
        rh: &Key,
        metrics: &dyn Metrics,
    ) -> Dispatch {
        let mut progress = Dispatch {
            delivered: BTreeSet::new(),
            block: BTreeSet::new(),
            pause_at: None,
            overflow_at: None,
        };
        let mut selected = 0u32;
        let mut calls = 0u32;
        let max_targets = self.budget.max_targets.max(1);
        // A duplicate-only group consumes a watermark read but no target
        // slot. Keep those reads within the Worker's alarm subrequest budget.
        let per_target_calls = self.budget.max_target_calls.map(|cap| cap.max(2));
        let total_call_cap = per_target_calls.map(|cap| cap.saturating_mul(max_targets));
        // Groups are ordered by their first sequence. Reaching the target
        // budget pauses at the next new target without marking it blocked.
        for (target, rows) in groups {
            if progress.pause_at.is_some_and(|at| rows[0].0 >= at) {
                break;
            }
            if blocked.binary_search(target).is_ok() {
                continue;
            }
            let call_limit = match (per_target_calls, total_call_cap) {
                (Some(per_target), Some(total)) => {
                    Some(per_target.min(total.saturating_sub(calls)))
                }
                _ => None,
            };
            if call_limit == Some(0) {
                progress.pause_at = Some(rows[0].0);
                break;
            }
            let target_rows = rows
                .iter()
                .map(|(seq, row, _, _)| (*seq, row.clone()))
                .collect::<Vec<_>>();
            let result = self
                .deliver_target(
                    target,
                    rh,
                    &target_rows,
                    call_limit,
                    selected < max_targets,
                    metrics,
                )
                .await;
            calls = calls.saturating_add(result.calls);
            selected += u32::from(result.selected);
            progress.delivered.extend(
                rows.iter()
                    .take(result.completed)
                    .map(|(seq, _, _, _)| *seq),
            );
            if result.failed {
                if blocked.len() + progress.block.len() == MAX_BLOCKED_TARGETS {
                    progress.overflow_at = Some(rows[result.completed].0);
                    break;
                }
                progress.block.insert(target.clone());
            } else if result.completed < rows.len() {
                // A healthy target cut by a row or Worker-call budget resumes
                // at its own first unattempted row on the next fire.
                progress.pause_at =
                    Some(progress.pause_at.map_or(rows[result.completed].0, |at| {
                        at.min(rows[result.completed].0)
                    }));
            }
        }
        progress
    }

    /// Returns the committed/duplicate prefix, retaining progress if a later chunk fails.
    #[allow(clippy::too_many_lines)] // One loop owns prefix shrinking, retry accounting and atomic delivery.
    async fn deliver_target(
        &self,
        target: &Partition,
        rh: &Key,
        rows: &[(u64, RelayV1)],
        call_limit: Option<u32>,
        allow_apply: bool,
        metrics: &dyn Metrics,
    ) -> TargetResult {
        let mut result = TargetResult {
            completed: 0,
            failed: false,
            selected: false,
            calls: 0,
        };
        while result.completed < rows.len() {
            let mut committed = false;
            for _ in 0..2 {
                if call_limit.is_some_and(|cap| result.calls >= cap) {
                    return result;
                }
                let mut prefix_end = result.completed
                    + fitting_prefix(
                        &Batch::new().require(Precondition::Absent(rh.clone())),
                        rh,
                        &rows[result.completed..],
                    );
                if prefix_end == result.completed {
                    result.failed = true;
                    return result;
                }
                let declared = loop {
                    let window = &rows[result.completed..prefix_end];
                    let (Ok(mut keys), Ok(counted)) = (
                        self.hook.read_keys(target, window),
                        repo_storage::relay_read_keys(target, window),
                    ) else {
                        result.failed = true;
                        return result;
                    };
                    keys.extend(counted);
                    let keys = keys.into_iter().collect::<BTreeSet<_>>();
                    if keys.len() + usize::from(!keys.contains(rh)) <= MAX_HOOK_READ_KEYS {
                        break keys;
                    }
                    if prefix_end == result.completed + 1 {
                        result.failed = true;
                        return result;
                    }
                    prefix_end = result.completed + (prefix_end - result.completed) / 2;
                };
                result.calls = result.calls.saturating_add(1);
                let snapshot = async {
                    let mut observations = Vec::new();
                    let observed = if declared.is_empty() {
                        self.target.get(target, rh).await?
                    } else {
                        let mut keys = vec![rh.clone()];
                        keys.extend(declared.into_iter().filter(|key| key != rh));
                        let values = self.target.get_many(target, &keys).await?;
                        if values.len() != keys.len() {
                            return Err(StoreError::Corrupt("short relay snapshot".into()));
                        }
                        observations = keys.into_iter().zip(values).collect();
                        observations[0].1.clone()
                    };
                    let hw = observed
                        .as_ref()
                        .map(codec::decode_u64)
                        .transpose()?
                        .unwrap_or(0);
                    Ok::<_, StoreError>((observed, hw, observations))
                }
                .await;
                let (observed, hw, observations) = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        tracing::warn!(?target, %error, "relay watermark read failed");
                        result.failed = true;
                        result.selected = true;
                        return result;
                    }
                };
                while result.completed < rows.len() && rows[result.completed].0 <= hw {
                    result.completed += 1;
                }
                if result.completed == rows.len() || !allow_apply {
                    return result;
                }
                if result.completed >= prefix_end {
                    continue;
                }
                result.selected = true;
                let Some((batch, end)) = self
                    .prepare_target_batch(
                        target,
                        rh,
                        &rows[..prefix_end],
                        observed.as_ref(),
                        result.completed,
                        &observations,
                        metrics,
                    )
                    .await
                else {
                    result.failed = true;
                    return result;
                };
                // Hook additions share the apply's atomicity and size boundary.
                if call_limit.is_some_and(|cap| result.calls >= cap) {
                    return result;
                }
                result.calls = result.calls.saturating_add(1);
                match self.target.apply(target, batch).await {
                    Ok(BatchOutcome::Committed) => {
                        result.completed = end;
                        committed = true;
                        break;
                    }
                    Ok(BatchOutcome::PreconditionFailed { .. }) => {}
                    other => {
                        tracing::warn!(?target, ?other, "relay target apply failed");
                        result.failed = true;
                        return result;
                    }
                }
            }
            if !committed {
                result.failed = true;
                return result;
            }
        }
        result
    }

    async fn prepare_target_batch(
        &self,
        target: &Partition,
        rh: &Key,
        rows: &[(u64, RelayV1)],
        observed: Option<&Value>,
        start: usize,
        observations: &[(Key, Option<Value>)],
        metrics: &dyn Metrics,
    ) -> Option<(Batch, usize)> {
        let base = Batch::new().require(match observed {
            Some(value) => Precondition::Equals(rh.clone(), value.clone()),
            None => Precondition::Absent(rh.clone()),
        });
        let mut end = start + fitting_prefix(&base, rh, &rows[start..]);
        if end == start {
            tracing::warn!(
                seq = rows[start].0,
                "relay row cannot fit one target batch; delivery to this target is stalled"
            );
            return None;
        }
        // A hook can use more space than the remaining headroom. Shrink a
        // combined group rather than stalling rows that fit individually.
        loop {
            let mut batch = target_batch(rh, observed, &rows[start..end]);
            // Stored-bytes counting is part of delivering to a coordinator,
            // not an embedder hook: markers applied uncounted could never be
            // counted afterwards.
            if let Err(error) = repo_storage::relay_extend(
                target,
                &rows[start..end],
                observations,
                &mut batch.preconditions,
                &mut batch.writes,
            ) {
                if matches!(&error, StoreError::Corrupt(m) if m.as_ref() == repo_storage::COUNTER_MISSING)
                {
                    metrics.incr(METRIC_RELAY_STORAGE_COUNTER_MISSING, &[], 1);
                }
                tracing::error!(?target, %error, "stored-bytes counting failed; rows stay queued");
                return None;
            }
            if let Err(error) = self
                .hook
                .before_apply_observed(
                    target,
                    &rows[start..end],
                    observations,
                    &mut batch.preconditions,
                    &mut batch.writes,
                )
                .await
            {
                if matches!(&error, StoreError::Invalid(message) if message.as_ref() == super::AUDIT_CAPACITY)
                    && end > start + 1
                {
                    end = start + (end - start) / 2;
                    continue;
                }
                tracing::warn!(?target, %error, "relay hook failed");
                return None;
            }
            let mut caps = self.target.capabilities();
            if !matches!(target, Partition::RefIndex { .. }) {
                caps.reserved_batch_ops = 0;
            }
            caps.reserved_batch_ops = caps
                .reserved_batch_ops
                .saturating_add(self.hook.reserved_ops(target, &rows[start..end]));
            if let Err(error) = batch.validate(&caps) {
                if matches!(error, StoreError::Invalid(_)) && end > start + 1 {
                    end = start + (end - start) / 2;
                    continue;
                }
                tracing::warn!(?target, %error, "relay target batch invalid");
                return None;
            }
            return Some((batch, end));
        }
    }
}

fn decode_window(
    source: &Partition,
    now_ms: u64,
    rows: Vec<(Key, Value)>,
    exhausted: bool,
) -> ScanWindow {
    let mut window = ScanWindow {
        rows: Vec::new(),
        groups: Vec::new(),
        corrupt: false,
        exhausted,
        lag_exceeded: false,
    };
    let mut warned_lag = false;
    for (key, value) in rows {
        let decoded = (|| {
            let Some(keys::ParsedKey::Relay(seq)) = keys::parse(&key) else {
                return Err(StoreError::Corrupt("bad relay queue key".into()));
            };
            if seq == 0 {
                return Err(StoreError::Corrupt("relay sequence is zero".into()));
            }
            Ok((seq, codec::decode_relay(&value)?))
        })();
        let (seq, row) = match decoded {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(source = ?source, ?key, %error, "corrupt relay row; tick stopped");
                window.corrupt = true;
                window.exhausted = false;
                break;
            }
        };
        if !warned_lag {
            let age_ms = now_ms.saturating_sub(row.at_ms);
            if age_ms > RELAY_LAG_BOUND_MS {
                tracing::warn!(source = ?source, age_ms, "outbox relay lag bound exceeded");
                warned_lag = true;
                window.lag_exceeded = true;
            }
        }
        let target = row.target.clone();
        window
            .rows
            .push((seq, target.clone(), key.clone(), value.clone()));
        let i = window
            .groups
            .iter()
            .position(|(partition, _)| partition == &target)
            .unwrap_or_else(|| {
                window.groups.push((target, Vec::new()));
                window.groups.len() - 1
            });
        window.groups[i].1.push((seq, row, key, value));
    }
    window
}

fn source_kind(source: &Partition) -> &'static str {
    match source {
        Partition::Ref { .. } => "ref",
        Partition::Namespace(_) => "namespace",
        Partition::Coordinator(_) => "coordinator",
        Partition::RepoIndex { .. } => "repo_index",
        Partition::RefIndex { .. } => "ref_index",
        Partition::ContentShard(_) => "content",
    }
}

async fn checkpoint_window<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    rs_key: &Key,
    observed: &mut Option<Value>,
    scan: &mut RelayScanV1,
    window: &ScanWindow,
    dispatch: &Dispatch,
) -> Result<bool, StoreError> {
    let mut staged = scan.clone();
    let mut deletions = Vec::new();
    let mut interrupted = false;
    let mut overflow = false;
    for (seq, target, key, value) in &window.rows {
        if dispatch.overflow_at.is_some_and(|at| *seq >= at) {
            overflow = true;
            break;
        }
        if dispatch.pause_at.is_some_and(|at| *seq >= at) {
            interrupted = true;
            break;
        }
        let mut next = staged.clone();
        next.cursor = *seq;
        if !dispatch.delivered.contains(seq)
            && let Err(at) = next.blocked.binary_search(target)
        {
            if !dispatch.block.contains(target) {
                interrupted = true;
                break;
            }
            if next.blocked.len() == MAX_BLOCKED_TARGETS {
                overflow = true;
                break;
            }
            next.blocked.insert(at, target.clone());
        }
        let mut candidate = deletions.clone();
        if dispatch.delivered.contains(seq) {
            candidate.push((key.clone(), value.clone()));
        }
        if checkpoint_batch(rs_key, observed.as_ref(), &next, &candidate)?
            .validate(&ctx.store.capabilities())
            .is_err()
        {
            if deletions.is_empty()
                || !apply_checkpoint(ctx, rs_key, observed, &staged, &deletions).await?
            {
                return Ok(false);
            }
            deletions.clear();
            checkpoint_batch(
                rs_key,
                observed.as_ref(),
                &next,
                &candidate[candidate.len() - usize::from(dispatch.delivered.contains(seq))..],
            )?
            .validate(&ctx.store.capabilities())?;
            if dispatch.delivered.contains(seq) {
                deletions.push((key.clone(), value.clone()));
            }
        } else {
            deletions = candidate;
        }
        staged = next;
    }
    let stopped_after = staged.cursor;
    if overflow {
        // Terminal marker: the next fire starts from the head with an empty
        // blocked set. The row that would exceed the cap is retained.
        staged.cursor = staged.cycle_end;
    } else if !window.corrupt && !interrupted && window.exhausted {
        // No more queued rows exist in this cycle's bounded sequence range;
        // missing sequence numbers are holes left by prior cleanup.
        staged.cursor = staged.cycle_end;
    }
    // Target batches can contain rows beyond a later target's pause or
    // overflow point. Their target watermark already covers those rows, so
    // delete them now instead of spending another fire on duplicate groups.
    // The cursor still stops before the uninspected row.
    for (seq, _, key, value) in &window.rows {
        if *seq <= stopped_after || !dispatch.delivered.contains(seq) {
            continue;
        }
        let mut candidate = deletions.clone();
        candidate.push((key.clone(), value.clone()));
        if checkpoint_batch(rs_key, observed.as_ref(), &staged, &candidate)?
            .validate(&ctx.store.capabilities())
            .is_err()
        {
            if deletions.is_empty()
                || !apply_checkpoint(ctx, rs_key, observed, &staged, &deletions).await?
            {
                return Ok(false);
            }
            deletions.clear();
            checkpoint_batch(
                rs_key,
                observed.as_ref(),
                &staged,
                &[(key.clone(), value.clone())],
            )?
            .validate(&ctx.store.capabilities())?;
            deletions.push((key.clone(), value.clone()));
        } else {
            deletions = candidate;
        }
    }
    if !apply_checkpoint(ctx, rs_key, observed, &staged, &deletions).await? {
        return Ok(false);
    }
    *scan = staged;
    Ok(true)
}

fn checkpoint_batch(
    rs_key: &Key,
    observed: Option<&Value>,
    state: &RelayScanV1,
    deletions: &[(Key, Value)],
) -> Result<Batch, StoreError> {
    let encoded = codec::encode_relay_scan(state)?;
    let guard = match observed {
        Some(value) => Precondition::Equals(rs_key.clone(), value.clone()),
        None => Precondition::Absent(rs_key.clone()),
    };
    let mut batch = Batch::new().require(guard).put(rs_key.clone(), encoded);
    for (key, value) in deletions {
        batch = batch
            .require(Precondition::Equals(key.clone(), value.clone()))
            .delete(key.clone());
    }
    Ok(batch)
}

async fn apply_checkpoint<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    rs_key: &Key,
    observed: &mut Option<Value>,
    state: &RelayScanV1,
    deletions: &[(Key, Value)],
) -> Result<bool, StoreError> {
    let batch = checkpoint_batch(rs_key, observed.as_ref(), state, deletions)?;
    batch.validate(&ctx.store.capabilities())?;
    let encoded = codec::encode_relay_scan(state)?;
    match ctx.store.apply(ctx.partition, batch).await? {
        BatchOutcome::Committed => {
            *observed = Some(encoded);
            Ok(true)
        }
        BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => Ok(false),
    }
}

fn fitting_prefix(base: &Batch, rh: &Key, rows: &[(u64, RelayV1)]) -> usize {
    let mut batch = base.clone();
    for (end, (seq, row)) in rows.iter().enumerate() {
        let mut candidate = batch.clone();
        candidate.writes.extend(
            row.puts
                .iter()
                .cloned()
                .map(|(key, value)| Write::Put(key, value)),
        );
        candidate
            .writes
            .extend(row.deletes.iter().cloned().map(Write::Delete));
        let sized = candidate.clone().put(rh.clone(), codec::encode_u64(*seq));
        if candidate.writes.len() > crate::store::outbox::MAX_RELAY_PUTS
            || sized.validate(&StoreCapabilities::full()).is_err()
        {
            return end;
        }
        batch = candidate;
    }
    rows.len()
}

fn target_batch(rh: &Key, observed: Option<&Value>, rows: &[(u64, RelayV1)]) -> Batch {
    let mut batch = Batch::new().require(match observed {
        Some(value) => Precondition::Equals(rh.clone(), value.clone()),
        None => Precondition::Absent(rh.clone()),
    });
    for (_, row) in rows {
        batch.writes.extend(
            row.puts
                .iter()
                .cloned()
                .map(|(key, value)| Write::Put(key, value)),
        );
        batch
            .writes
            .extend(row.deletes.iter().cloned().map(Write::Delete));
    }
    batch.put(
        rh.clone(),
        codec::encode_u64(rows.last().expect("non-empty relay batch").0),
    )
}

async fn read_rows<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    state: &RelayScanV1,
    limit: u32,
) -> Result<(Vec<(Key, Value)>, bool), StoreError> {
    if state.cursor >= state.cycle_end || limit == 0 {
        return Ok((Vec::new(), true));
    }
    // Include the exact cursor key (which may remain for a blocked target)
    // so malformed keys between it and the next sequence cannot be skipped.
    // At cursor zero the class head also catches malformed keys before seq 1.
    let anchor = (state.cursor != 0).then(|| keys::relay(state.cursor));
    let start = anchor
        .clone()
        .unwrap_or_else(|| keys::class_range(keys::TAG_RELAY).0);
    let end = state
        .cycle_end
        .checked_add(1)
        .map_or_else(|| keys::class_range(keys::TAG_RELAY).1, keys::relay);
    let mut rows = Vec::new();
    let mut encoded_bytes = 0;
    let mut remaining = limit;
    let mut cursor = None;
    loop {
        let page = ctx
            .store
            .scan(
                ctx.partition,
                &start,
                &end,
                cursor.as_ref(),
                SCAN_PAGE_ROWS.min(remaining),
            )
            .await?;
        for (key, value) in page.entries {
            remaining -= 1;
            if anchor.as_ref() == Some(&key) {
                continue;
            }
            let size = key.as_bytes().len() + value.as_bytes().len();
            if !rows.is_empty() && encoded_bytes + size > MAX_FIRE_BYTES {
                return Ok((rows, false));
            }
            encoded_bytes += size;
            rows.push((key, value));
        }
        if remaining == 0 || page.next.is_none() {
            return Ok((rows, page.next.is_none()));
        }
        cursor = page.next;
    }
}
