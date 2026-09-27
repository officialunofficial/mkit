//! Ordered target batches, guarded watermarks, and bounded source cleanup.

use super::{NoHook, RELAY_LAG_BOUND_MS, RelayBudget, RelayHook};
use crate::rt::BoxFuture;
use crate::store::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreCapabilities,
    StoreError, Value, Write,
    codec::{self, RelayV1},
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
        let observed_os = ctx.store.get(ctx.partition, &os_key).await?;
        let rows = read_rows(ctx, self.budget.max_rows.max(1)).await?;
        // Decode all inspected rows before making progress: corruption is never skipped.
        let mut groups: Vec<TargetRows> = Vec::new();
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
                    tracing::warn!(source = ?ctx.partition, ?key, %error, "corrupt relay row; tick stopped");
                    return Ok(Fired::Retry);
                }
            };
            if groups.is_empty() {
                let age_ms = ctx.now_ms.saturating_sub(row.at_ms);
                if age_ms > RELAY_LAG_BOUND_MS {
                    tracing::warn!(source = ?ctx.partition, age_ms, "outbox relay lag bound exceeded");
                }
            }
            let i = groups
                .iter()
                .position(|(p, _)| p == &row.target)
                .unwrap_or_else(|| {
                    groups.push((row.target.clone(), Vec::new()));
                    groups.len() - 1
                });
            groups[i].1.push((seq, row, key, value));
        }
        let rh = keys::relay_high_water(ctx.partition)?;
        let mut delivered = Vec::new();
        let mut failed = false;
        for (target, rows) in groups
            .into_iter()
            .take(self.budget.max_targets.max(1) as usize)
        {
            let target_rows = rows
                .iter()
                .map(|(seq, row, _, _)| (*seq, row.clone()))
                .collect::<Vec<_>>();
            let count = self.deliver_target(&target, &rh, &target_rows).await;
            if count < rows.len() {
                failed = true;
            }
            delivered.extend(
                rows.into_iter()
                    .take(count)
                    .map(|(_, _, key, value)| (key, value)),
            );
        }
        delete_rows(ctx, delivered).await?;
        let (start, end) = keys::class_range(keys::TAG_RELAY);
        let remaining = ctx.store.scan(ctx.partition, &start, &end, None, 1).await?;
        if !remaining.entries.is_empty() || remaining.next.is_some() {
            // Successful reschedules do not invoke core failure backoff. Explicitly
            // back off failures; budget continuations only need a distinct key.
            let due = ctx
                .now_ms
                .saturating_add(if failed { RETRY_BACKOFF_MS } else { 0 })
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
            Ok(Fired::Done(Batch::new().require(match observed_os {
                Some(value) => Precondition::Equals(os_key, value),
                None => Precondition::Absent(os_key),
            })))
        }
    }

    /// Returns the committed/duplicate prefix, retaining progress if a later chunk fails.
    async fn deliver_target(&self, target: &Partition, rh: &Key, rows: &[(u64, RelayV1)]) -> usize {
        let mut completed = 0;
        while completed < rows.len() {
            let mut committed = false;
            for _ in 0..2 {
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
                        return completed;
                    }
                };
                while completed < rows.len() && rows[completed].0 <= hw {
                    completed += 1;
                }
                if completed == rows.len() {
                    return completed;
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
                    return completed;
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
                        return completed;
                    }
                    if let Err(error) = extended.validate(&self.target.capabilities()) {
                        if matches!(error, StoreError::Invalid(_)) && end > completed + 1 {
                            end = completed + (end - completed) / 2;
                            continue;
                        }
                        tracing::warn!(?target, %error, "relay target batch invalid");
                        return completed;
                    }
                    batch = extended;
                    break;
                }
                // Hook additions share the apply's atomicity and size boundary.
                match self.target.apply(target, batch).await {
                    Ok(BatchOutcome::Committed) => {
                        completed = end;
                        committed = true;
                        break;
                    }
                    Ok(BatchOutcome::PreconditionFailed { .. }) => {}
                    other => {
                        tracing::warn!(?target, ?other, "relay target apply failed");
                        return completed;
                    }
                }
            }
            if !committed {
                return completed;
            }
        }
        completed
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
    limit: u32,
) -> Result<Vec<(Key, Value)>, StoreError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let (start, end) = keys::class_range(keys::TAG_RELAY);
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
            let size = key.as_bytes().len() + value.as_bytes().len();
            if !rows.is_empty() && encoded_bytes + size > MAX_FIRE_BYTES {
                return Ok(rows);
            }
            encoded_bytes += size;
            rows.push((key, value));
            remaining -= 1;
        }
        if remaining == 0 || page.next.is_none() {
            return Ok(rows);
        }
        cursor = page.next;
    }
}

async fn delete_rows<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    rows: Vec<(Key, Value)>,
) -> Result<(), StoreError> {
    let mut batch = Batch::new();
    for (key, value) in rows {
        let mut candidate = batch
            .clone()
            .require(Precondition::Equals(key.clone(), value.clone()))
            .delete(key.clone());
        if candidate.validate(&StoreCapabilities::full()).is_err() {
            ctx.store.apply(ctx.partition, batch).await?;
            candidate = Batch::new()
                .require(Precondition::Equals(key.clone(), value))
                .delete(key);
        }
        batch = candidate;
    }
    if !batch.writes.is_empty() {
        ctx.store.apply(ctx.partition, batch).await?;
    }
    // A raced cleanup leaves rows for the next fire, which skips them via rh.
    Ok(())
}
