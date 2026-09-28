//! Ordered target batches, guarded watermarks, and bounded source cleanup.

use std::collections::BTreeSet;

use super::{NoHook, RELAY_LAG_BOUND_MS, RelayBudget, RelayHook};
use crate::rt::BoxFuture;
use crate::store::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreCapabilities,
    StoreError, Value, Write,
    codec::{self, MAX_BLOCKED_TARGETS, RelayScanV1, RelayV1},
    keys,
};
use crate::timers::{
    DueTimer, Fired, RETRY_BACKOFF_MS, TimerCtx, TimerHandler, TimerKind, registry::kinds,
};

// Keep encoded pages and decoded groups comfortably below a Worker isolate's
// 128 MiB limit, even when rows approach MAX_VALUE_BYTES. The row/target budget
// remains an upper bound; leftover rows schedule another tick.
const MAX_FIRE_BYTES: usize = 4 * 1024 * 1024;
const SCAN_PAGE_ROWS: u32 = 4;

type QueuedRow = (u64, RelayV1, Key, Value);
type TargetRows = (Partition, Vec<QueuedRow>);
type InspectedRow = (u64, Partition, Key, Value);

struct ScanWindow {
    rows: Vec<InspectedRow>,
    groups: Vec<TargetRows>,
    corrupt: bool,
    exhausted: bool,
}

struct Dispatch {
    delivered: BTreeSet<u64>,
    block: BTreeSet<Partition>,
    pause_at: Option<u64>,
    overflow_at: Option<u64>,
}

/// Pushes a source's queued rows to a separately supplied target store.
/// Each source/key must have exactly one producer; target rh rows never expire.
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
        Box::pin(self.deliver(ctx, timer))
    }
}

impl<T: NamespaceStore, H: RelayHook> RelayHandler<T, H> {
    async fn deliver<S: NamespaceStore>(
        &self,
        ctx: &TimerCtx<'_, S>,
        timer: &DueTimer,
    ) -> Result<Fired, StoreError> {
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
        let rh = keys::relay_high_water(ctx.partition)?;
        let dispatch = self.dispatch(&window.groups, &scan.blocked, &rh).await;
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
            let (start, end) = keys::class_range(keys::TAG_RELAY);
            let remaining = ctx.store.scan(ctx.partition, &start, &end, None, 1).await?;
            !remaining.entries.is_empty() || remaining.next.is_some()
        };
        if has_remaining {
            let due = ctx
                .now_ms
                .saturating_add(if dispatch.delivered.is_empty() {
                    RETRY_BACKOFF_MS
                } else {
                    0
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

    async fn dispatch(&self, groups: &[TargetRows], blocked: &[Partition], rh: &Key) -> Dispatch {
        let mut progress = Dispatch {
            delivered: BTreeSet::new(),
            block: BTreeSet::new(),
            pause_at: None,
            overflow_at: None,
        };
        let mut selected = 0usize;
        // Groups are ordered by their first sequence. Reaching the target
        // budget pauses at the next new target without marking it blocked.
        for (target, rows) in groups {
            if progress.pause_at.is_some_and(|at| rows[0].0 >= at) {
                break;
            }
            if blocked.binary_search(target).is_ok() {
                continue;
            }
            if selected >= self.budget.max_targets.max(1) as usize {
                progress.pause_at = Some(rows[0].0);
                break;
            }
            selected += 1;
            let target_rows = rows
                .iter()
                .map(|(seq, row, _, _)| (*seq, row.clone()))
                .collect::<Vec<_>>();
            let (count, failed) = self.deliver_target(target, rh, &target_rows).await;
            progress
                .delivered
                .extend(rows.iter().take(count).map(|(seq, _, _, _)| *seq));
            if failed {
                if blocked.len() + progress.block.len() == MAX_BLOCKED_TARGETS {
                    progress.overflow_at = Some(rows[count].0);
                    break;
                }
                progress.block.insert(target.clone());
            } else if count < rows.len() {
                // A healthy target cut by a row or Worker-call budget resumes
                // at its own first unattempted row on the next fire.
                progress.pause_at = Some(
                    progress
                        .pause_at
                        .map_or(rows[count].0, |at| at.min(rows[count].0)),
                );
            }
        }
        progress
    }

    /// Returns the committed/duplicate prefix, retaining progress if a later chunk fails.
    async fn deliver_target(
        &self,
        target: &Partition,
        rh: &Key,
        rows: &[(u64, RelayV1)],
    ) -> (usize, bool) {
        let mut completed = 0;
        let mut calls = 0u32;
        while completed < rows.len() {
            let mut committed = false;
            for _ in 0..2 {
                if self.budget.max_target_calls.is_some_and(|cap| calls >= cap) {
                    return (completed, false);
                }
                calls = calls.saturating_add(1);
                let snapshot = async {
                    let observed = self.target.get(target, rh).await?;
                    let hw = observed
                        .as_ref()
                        .map(codec::decode_u64)
                        .transpose()?
                        .unwrap_or(0);
                    Ok::<_, StoreError>((observed, hw))
                }
                .await;
                let (observed, hw) = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        tracing::warn!(?target, %error, "relay watermark read failed");
                        return (completed, true);
                    }
                };
                while completed < rows.len() && rows[completed].0 <= hw {
                    completed += 1;
                }
                if completed == rows.len() {
                    return (completed, false);
                }
                let mut batch = Batch::new().require(match observed {
                    Some(value) => Precondition::Equals(rh.clone(), value),
                    None => Precondition::Absent(rh.clone()),
                });
                let mut end = completed + fitting_prefix(&batch, rh, &rows[completed..]);
                if end == completed {
                    tracing::warn!(
                        seq = rows[completed].0,
                        "relay row cannot fit one target batch; delivery to this target is stalled"
                    );
                    return (completed, true);
                }
                // A hook can use more space than the remaining headroom. Shrink
                // a combined group rather than stalling rows that fit individually.
                loop {
                    let snapshot = match &batch.preconditions[0] {
                        Precondition::Equals(_, value) => Some(value),
                        _ => None,
                    };
                    let mut extended = target_batch(rh, snapshot, &rows[completed..end]);
                    if let Err(error) = self
                        .hook
                        .before_apply(
                            target,
                            &rows[completed..end],
                            &mut extended.preconditions,
                            &mut extended.writes,
                        )
                        .await
                    {
                        tracing::warn!(?target, %error, "relay hook failed");
                        return (completed, true);
                    }
                    if let Err(error) = extended.validate(&self.target.capabilities()) {
                        if matches!(error, StoreError::Invalid(_)) && end > completed + 1 {
                            end = completed + (end - completed) / 2;
                            continue;
                        }
                        tracing::warn!(?target, %error, "relay target batch invalid");
                        return (completed, true);
                    }
                    batch = extended;
                    break;
                }
                // Hook additions share the apply's atomicity and size boundary.
                if self.budget.max_target_calls.is_some_and(|cap| calls >= cap) {
                    return (completed, false);
                }
                calls = calls.saturating_add(1);
                match self.target.apply(target, batch).await {
                    Ok(BatchOutcome::Committed) => {
                        completed = end;
                        committed = true;
                        break;
                    }
                    Ok(BatchOutcome::PreconditionFailed { .. }) => {}
                    other => {
                        tracing::warn!(?target, ?other, "relay target apply failed");
                        return (completed, true);
                    }
                }
            }
            if !committed {
                return (completed, true);
            }
        }
        (completed, false)
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
    if overflow {
        // Terminal marker: the next fire starts from the head with an empty
        // blocked set. The row that would exceed the cap is retained.
        staged.cursor = staged.cycle_end;
    } else if !window.corrupt && !interrupted && window.exhausted {
        // No more queued rows exist in this cycle's bounded sequence range;
        // missing sequence numbers are holes left by prior cleanup.
        staged.cursor = staged.cycle_end;
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
