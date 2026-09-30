use super::{DEBOUNCE_MS, Envelope, MAX_ROWS, REFRESH_MS, SnapshotBucket, VALIDITY_MS, object_key};
use mkit_server::pipeline::list::{BucketSource, IndexBucket};
use mkit_server::sql::SqlError;
use mkit_server::store::{Key, codec, keys};
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use mkit_server::{
    Batch, BoxFuture, Clock, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

/// Worker `RefIndex` metadata: version, generation, dirty, timer due, last success.
#[must_use]
pub fn state_key() -> Key {
    Key::new(b"ps\0".to_vec())
}
#[derive(Debug, Clone)]
pub(super) struct State {
    pub(super) generation: u64,
    pub(super) dirty: bool,
    pub(super) due: u64,
    pub(super) last_success: u64,
}
impl State {
    pub(super) fn encode(&self) -> Value {
        let mut b = vec![1, u8::from(self.dirty)];
        for v in [self.generation, self.due, self.last_success] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        Value::new(b)
    }
    pub(super) fn decode(v: &Value) -> Result<Self, SqlError> {
        let b = v.as_bytes();
        if b.len() != 26 || b[0] != 1 || b[1] > 1 {
            return Err(SqlError::Corrupt("snapshot state"));
        }
        let get = |at| {
            b.get(at..at + 8)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(SqlError::Corrupt("snapshot state"))
        };
        let generation = get(2)?;
        if generation == 0 {
            return Err(SqlError::Corrupt("snapshot generation"));
        }
        Ok(Self {
            generation,
            dirty: b[1] != 0,
            due: get(10)?,
            last_success: get(18)?,
        })
    }
}
fn timer_key(due: u64) -> Key {
    keys::timer(due, kinds::PUBLISHED_VIEW.get(), b"")
}

/// Extend an index relay batch after its watermark guard holds, inside SQL apply.
/// Three operations of headroom cover state, old timer deletion and new timer `Put`.
pub fn extend_relay(
    partition: &Partition,
    get: &dyn Fn(&Key) -> Result<Option<Value>, SqlError>,
    batch: &mut Batch,
    now_ms: u64,
) -> Result<Option<u64>, SqlError> {
    if !matches!(partition, Partition::RefIndex { .. }) {
        return Ok(None);
    }
    let changes_index = batch.writes.iter().any(|w| {
        let key = match w {
            Write::Put(k, _) | Write::Delete(k) => k,
        };
        matches!(
            keys::parse(key),
            Some(keys::ParsedKey::PublishedIndex { .. })
        )
    });
    if !changes_index {
        return Ok(None);
    }
    let mut state = get(&state_key())?
        .as_ref()
        .map(State::decode)
        .transpose()?
        .unwrap_or(State {
            generation: 0,
            dirty: false,
            due: 0,
            last_success: 0,
        });
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or(SqlError::Corrupt("snapshot generation overflow"))?;
    // Do not postpone a burst. A stale timer pointer after a driver backoff is
    // repaired locally; that old timer will be drained by the handler.
    let exists = state.due != 0 && get(&timer_key(state.due))?.is_some();
    let due = now_ms
        .saturating_add(DEBOUNCE_MS)
        .max(state.last_success.saturating_add(DEBOUNCE_MS));
    if !exists || (!state.dirty && state.due > due) {
        if exists {
            batch.writes.push(Write::Delete(timer_key(state.due)));
        }
        state.due = due;
        batch
            .writes
            .push(Write::Put(timer_key(due), Value::default()));
    }
    state.dirty = true;
    batch.writes.push(Write::Put(state_key(), state.encode()));
    Ok(Some(state.due))
}
/// Shared across every partition head in one alarm. `RefIndex` makes at most
/// one visibility `GET`, one R2 `GET` and one `PUT`/delete (<=3 of its 8-call cap).
#[derive(Debug, Clone, Default)]
pub struct SnapshotAlarm(Arc<AtomicBool>, Arc<AtomicUsize>);
impl SnapshotAlarm {
    /// Reset once at alarm entry, never once per partition.
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
        self.1.store(0, Ordering::SeqCst);
    }
    /// Reserve external calls conservatively across every head, including backup.
    #[must_use]
    pub fn reserve(&self, calls: usize) -> bool {
        self.1
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(calls).filter(|total| *total <= 8)
            })
            .is_ok()
    }
    fn claim(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst) && self.reserve(3)
    }
}
/// Kind 10 is registered only on configured `RepoIndexShard` objects.
pub struct SnapshotHandler<B, N> {
    /// Dedicated snapshot bucket.
    pub bucket: B,
    /// Coordinator-only remote visibility reads.
    pub coordinator: N,
    /// Clock read again after external awaits for replacement spacing.
    pub clock: Arc<dyn Clock>,
    /// Alarm-wide fire cap.
    pub alarm: SnapshotAlarm,
}
impl<B, N> core::fmt::Debug for SnapshotHandler<B, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotHandler")
            .field("alarm", &self.alarm)
            .finish_non_exhaustive()
    }
}
/// Share the configured `RefIndex` alarm's external budget with backup fires.
#[derive(Debug)]
pub struct AlarmLimited<H> {
    /// Existing backup handler (unchanged outside configured `RepoIndexShard`).
    pub handler: H,
    /// Alarm-wide call allowance.
    pub alarm: SnapshotAlarm,
}
impl<S: NamespaceStore, H: TimerHandler<S>> TimerHandler<S> for AlarmLimited<H> {
    fn kind(&self) -> TimerKind {
        self.handler.kind()
    }
    fn max_per_tick(&self) -> Option<u32> {
        self.handler.max_per_tick()
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            if self.alarm.reserve(1) {
                self.handler.fire(ctx, timer).await
            } else {
                Ok(Fired::Reschedule {
                    due_at_ms: ctx
                        .now_ms
                        .saturating_add(DEBOUNCE_MS)
                        .max(timer.due_at_ms.saturating_add(1)),
                    value: timer.value.clone(),
                    batch: Batch::new(),
                })
            }
        })
    }
}
impl<B: SnapshotBucket, N: NamespaceStore, S: NamespaceStore> TimerHandler<S>
    for SnapshotHandler<B, N>
{
    fn kind(&self) -> TimerKind {
        kinds::PUBLISHED_VIEW
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let Some(observed) = ctx.store.get(ctx.partition, &state_key()).await? else {
                return Ok(Fired::Done(Batch::new()));
            };
            let mut state = State::decode(&observed).map_err(StoreError::from)?;
            if state.due != timer.due_at_ms || !timer.reference.is_empty() {
                return Ok(Fired::Done(Batch::new()));
            }
            let due = if self.alarm.claim() {
                match self.publish(ctx, &state).await {
                    Ok(next) => {
                        state.dirty = false;
                        state.last_success = self.now();
                        next
                    }
                    Err(error) => {
                        crate::log_failure(&format!("published snapshot failed: {error}"));
                        self.now().saturating_add(DEBOUNCE_MS)
                    }
                }
            } else {
                ctx.now_ms.saturating_add(DEBOUNCE_MS)
            };
            state.due = due.max(timer.due_at_ms.saturating_add(1));
            // A concurrent relay cannot have its generation or earlier wake cleared.
            Ok(Fired::Reschedule {
                due_at_ms: state.due,
                value: Value::default(),
                batch: Batch::new()
                    .require(Precondition::Equals(state_key(), observed))
                    .put(state_key(), state.encode()),
            })
        })
    }
}
impl<B: SnapshotBucket, N: NamespaceStore> SnapshotHandler<B, N> {
    fn now(&self) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(0)
    }
    async fn publish<S: NamespaceStore>(
        &self,
        ctx: &TimerCtx<'_, S>,
        state: &State,
    ) -> Result<u64, StoreError> {
        let Partition::RefIndex { ns, repo, .. } = ctx.partition else {
            return Err(StoreError::Invalid("snapshot outside RefIndex".into()));
        };
        let identity = mkit_server::RepoId {
            namespace: ns.clone(),
            name: repo.clone(),
        };
        // On Worker these local SQL futures finish synchronously, before the
        // first external await; generation and rows describe one captured view.
        if !matches!(
            mkit_server::store::migration::observe(ctx.store, ctx.partition, repo).await?,
            mkit_server::store::migration::State::Managed
        ) {
            return Err(StoreError::unavailable("publication migration incomplete"));
        }
        let captured_at_ms = self.now();
        let view = mkit_server::store::view::ViewStore {
            store: ctx.store,
            repo: &identity,
            writer: false,
            policy: None,
        };
        let scan = IndexBucket {
            store: &view,
            partition: ctx.partition,
        }
        .scan(
            &identity,
            "",
            None,
            u32::try_from(MAX_ROWS + 1).unwrap_or(u32::MAX),
        )
        .await?;
        if !matches!(
            mkit_server::store::migration::observe(ctx.store, ctx.partition, repo).await?,
            mkit_server::store::migration::State::Managed
        ) {
            return Err(StoreError::unavailable("publication migration incomplete"));
        }
        let envelope = Envelope {
            partition: ctx.partition.clone(),
            generation: state.generation,
            captured_at_ms,
            valid_until_ms: captured_at_ms.saturating_add(VALIDITY_MS),
            rows: scan.rows,
        };
        let encoded = if scan.more {
            None
        } else {
            envelope.encode().ok()
        };
        let rows = self
            .coordinator
            .get_many(
                &Partition::Coordinator(ns.clone()),
                &[keys::repo_record(repo), keys::repo_visibility(repo)],
            )
            .await?;
        let present = rows
            .first()
            .and_then(Option::as_ref)
            .map(codec::decode_repo_record)
            .transpose()?
            .is_some();
        let private = rows
            .get(1)
            .and_then(Option::as_ref)
            .map(codec::decode_repo_visibility)
            .transpose()?
            .is_some_and(|v| v.visibility == codec::StoredVisibility::Private);
        let key = object_key(ctx.partition)?;
        if !present || private || encoded.is_none() {
            self.bucket.delete(&key).await?;
            return Ok(self.now().saturating_add(REFRESH_MS));
        }
        let previous = self.bucket.get(&key).await?;
        if let Some(old) = &previous {
            // Storage time, rather than capture time, survives slow uploads,
            // crash-after-put and re-entrant relay delivery.
            let earliest = old.stored_at_ms.saturating_add(DEBOUNCE_MS);
            if self.now() < earliest {
                return Err(StoreError::unavailable("snapshot replacement debounced"));
            }
            // Validate old identity/version too. Expired content still carries
            // a generation, using its original capture time for decoding.
            let old_envelope =
                Envelope::decode(&old.bytes, ctx.partition, old_capture_time(&old.bytes)?)?;
            if old_envelope.generation > state.generation
                || (old_envelope.generation == state.generation
                    && old_envelope.captured_at_ms > captured_at_ms)
            {
                return Err(StoreError::unavailable("newer snapshot exists"));
            }
        }
        if self.now() >= envelope.valid_until_ms {
            return Err(StoreError::unavailable("snapshot expired during capture"));
        }
        let Some(encoded) = encoded else {
            return Err(StoreError::Corrupt("missing snapshot encoding".into()));
        };
        if !self
            .bucket
            .replace(&key, previous.as_ref().map(|o| o.etag.as_str()), encoded)
            .await?
        {
            return Err(StoreError::unavailable("snapshot ETag conflict"));
        }
        Ok(self.now().saturating_add(REFRESH_MS))
    }
}
fn old_capture_time(bytes: &[u8]) -> Result<u64, StoreError> {
    let length = bytes
        .get(4..6)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| StoreError::Corrupt("snapshot header".into()))?;
    let offset = 6 + usize::from(length) + 8;
    bytes
        .get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| StoreError::Corrupt("snapshot capture time".into()))
}
