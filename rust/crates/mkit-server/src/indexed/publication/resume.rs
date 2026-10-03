//! Pair-bound closure evidence in the existing verified MKPL state row.
//! Immutable sealed inventories replace repeated canonical reconstruction.
use super::{PairStore, capped, closed, unavailable};
use crate::indexed::{IndexedConfig, budget::SliceBudget, resolve, state};
use crate::pipeline::{D34Shards, ShardMap, SinglePartition, clearance::Immediate};
use crate::store::{
    keys,
    publication::{Advance, MAX_ADVANCE_ITEMS, Pair},
};
use crate::takedown::{denial, inventory};
use crate::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, RepoId, ServerError, StoreError,
    Value,
};
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};

/// Includes metadata reads; timer settlement is outside this existing allowance.
pub const SLICE_CALLS: u32 = crate::timers::publication_recheck::MAX_RECHECK_CALLS;
/// Reserve prior-value guard, keys and timer settlement within one batch.
pub const MAX_STATE_BYTES: usize =
    (crate::store::MAX_BATCH_BYTES - 8 * crate::store::MAX_KEY_BYTES) / 2;
/// Whole-pair ceiling, retained across alarms and foreground retries.
pub const TOTAL_CALLS: u64 = 1_048_576;
/// Canonical lengths charged per slice without retaining any canonical bytes.
pub const SLICE_BYTES: u64 = 8 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exhaustion {
    DecodeBudget,
    IndexCalls,
    Traversal,
    /// A per-lookup index cap on the pair's own content (an input limit).
    IndexLookup,
}
impl Exhaustion {
    fn error(self) -> ServerError {
        match self {
            Self::DecodeBudget => ServerError::invalid_argument(resolve::DECODE_BUDGET_MESSAGE),
            // The same specified error as the canonical path's lookup cap.
            Self::IndexLookup => capped(),
            // Unsupported historical capacity: the content was never judged
            // invalid, and retrying the same pair cannot succeed.
            Self::IndexCalls | Self::Traversal => {
                crate::pipeline::publication_budget::PublicationBudget::limit_error()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum TerminalFailure {
    OpenClosure,
    DeltaDepth,
}
impl TerminalFailure {
    fn error(self) -> ServerError {
        ServerError::invalid_argument(match self {
            Self::OpenClosure => "open closure",
            Self::DeltaDepth => "delta chain too deep",
        })
    }
}

/// Verified pack state may carry exactly one frozen pair's resumable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    binding: Hash,
    value: Pair,
    generation: u64,
    additions: Vec<Hash>,
    next_packmap: Option<Hash>,
    chain: BTreeSet<Hash>,
    packs: BTreeSet<Hash>,
    queue: VecDeque<Hash>,
    visited: BTreeSet<Hash>,
    dependencies: BTreeSet<Hash>,
    bases: BTreeSet<Hash>,
    bytes: u64,
    calls: u64,
    byte_limit: u64,
    depth_limit: u32,
    base_cursor: Option<BaseCursor>,
    failure: Option<Exhaustion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<TerminalFailure>,
    missing: bool,
    missing_base: bool,
    complete: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseCursor {
    origin: Hash,
    next: Hash,
    depth: u32,
}
impl Progress {
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        let frozen = serde_json::to_vec(&(
            self.value.clone(),
            self.generation,
            self.additions.clone(),
            self.byte_limit,
            self.depth_limit,
        ))
        .map_err(|_| StoreError::Corrupt("invalid publication binding".into()))?;
        if hash(&frozen) != self.binding {
            return Err(StoreError::Corrupt("publication binding mismatch".into()));
        }
        if [
            self.chain.len(),
            self.packs.len(),
            self.queue.len(),
            self.visited.len(),
            self.dependencies.len(),
            self.bases.len(),
        ]
        .into_iter()
        .any(|n| n > MAX_ADVANCE_ITEMS)
            || self.additions.len() > crate::store::outbox::MAX_TICKETS_PER_ADVANCE
            || self.calls > TOTAL_CALLS + u64::from(SLICE_CALLS)
            || self.bytes > self.byte_limit && self.failure != Some(Exhaustion::DecodeBudget)
            || self.complete
                && (self.next_packmap.is_some()
                    || !self.queue.is_empty()
                    || self.base_cursor.is_some()
                    || self.failure.is_some()
                    || self.terminal.is_some()
                    || self.missing
                    || self.value.head.is_some_and(|h| !self.visited.contains(&h))
                    || self.value.packmap.is_some_and(|m| !self.chain.contains(&m))
                    || !self.chain.is_subset(&self.dependencies)
                    || !self.packs.is_subset(&self.dependencies))
        {
            return Err(StoreError::Corrupt(
                "invalid publication verification progress".into(),
            ));
        }
        Ok(())
    }
    fn result(
        &self,
        advance: &mut Advance,
        now: u64,
        created: u64,
        lag: u64,
    ) -> Result<(), ServerError> {
        if let Some(failure) = self.failure {
            return Err(failure.error());
        }
        if let Some(failure) = self.terminal {
            return Err(failure.error());
        }
        if self.missing {
            return Err(if self.missing_base {
                resolve::missing_base(now, created, lag)
            } else {
                crate::indexed::verify::closure_error(now, created, lag)
            });
        }
        if !self.complete {
            return Err(crate::indexed::pending(1_000));
        }
        advance.dependencies = self.dependencies.iter().copied().collect();
        advance.external_bases = self.bases.iter().copied().collect();
        Ok(())
    }
}

// A state that cannot fit is terminal, rather than an alarm that repeats the
// same oversized frontier forever. Retain binding/counters and the typed cause.
fn bounded_state(state: &mut state::VerificationV1) -> Value {
    let encoded = state::encode(state);
    if encoded.as_bytes().len() <= MAX_STATE_BYTES {
        return encoded;
    }
    if let state::VerificationV1::Verified {
        publication: Some(p),
        ..
    } = state
    {
        p.failure.get_or_insert(Exhaustion::Traversal);
        p.next_packmap = None;
        p.base_cursor = None;
        p.chain.clear();
        p.packs.clear();
        p.queue.clear();
        p.visited.clear();
        p.dependencies.clear();
        p.bases.clear();
        p.complete = false;
        p.missing = false;
        p.missing_base = false;
    }
    state::encode(state)
}

fn binding(advance: &Advance, cfg: IndexedConfig) -> Result<Hash, ServerError> {
    let bytes = serde_json::to_vec(&(
        advance.value.clone(),
        advance.generation,
        advance.additions.clone(),
        cfg.decode_budget,
        cfg.max_delta_chain_depth,
    ))
    .map_err(|_| unavailable())?;
    Ok(hash(&bytes))
}

/// First slice may complete inline. Otherwise only verification state and timer
/// are written; no ref, membership, outcome or ticket is accepted/consumed.
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // Immutable proof inputs plus the consuming request lag context.
pub(crate) async fn prepare<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &mut Advance,
    cfg: IndexedConfig,
    now: u64,
    metrics: &dyn crate::Metrics,
    created: u64,
) -> Result<bool, ServerError> {
    prepare_with(
        store, source, shards, repo, advance, cfg, now, metrics, created, None, None,
    )
    .await
}

/// [`prepare`] whose slice draws from the foreground request's ledger.
#[allow(clippy::too_many_arguments)] // Immutable proof inputs plus the consuming request lag context.
#[allow(clippy::too_many_lines)] // One checkpointed foreground slice with its settlement metering.
pub(crate) async fn prepare_with<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &mut Advance,
    cfg: IndexedConfig,
    now: u64,
    metrics: &dyn crate::Metrics,
    created: u64,
    request: Option<&SliceBudget>,
    settle: Option<&SliceBudget>,
) -> Result<bool, ServerError> {
    // Reads of the verification row and the checkpoint write are settlement:
    // they charge the request root, never the proof share.
    let meter = crate::pipeline::publication_budget::PublicationBudget::meter(settle);
    let metered = crate::indexed::budget::Budgeted::new(store, &meter);
    let Some(root) = advance.value.packmap else {
        return Ok(false);
    };
    let Some((mut state, prior)) = state::read(&metered, source, &repo.name, &root)
        .await
        .map_err(|_| unavailable())?
    else {
        return Ok(false);
    };
    let state::VerificationV1::Verified { publication, .. } = &mut state else {
        return Err(crate::indexed::pending(1_000));
    };
    let wanted = binding(advance, cfg)?;
    if let Some(progress) = publication
        .as_ref()
        .filter(|p| p.binding == wanted && !p.missing)
    {
        return progress
            .result(advance, now, created, cfg.relay_lag_bound_ms)
            .map(|()| true);
    }
    let mut progress = if let Some(old) = publication.as_ref().filter(|p| p.binding == wanted) {
        let mut resumed = (**old).clone();
        resumed.missing = false;
        resumed
    } else {
        Progress {
            binding: wanted,
            value: advance.value.clone(),
            generation: advance.generation,
            additions: advance.additions.clone(),
            next_packmap: Some(root),
            chain: BTreeSet::new(),
            packs: BTreeSet::new(),
            queue: VecDeque::from_iter(advance.value.head),
            visited: BTreeSet::new(),
            dependencies: BTreeSet::new(),
            bases: BTreeSet::new(),
            bytes: 0,
            calls: 0,
            byte_limit: cfg.decode_budget,
            depth_limit: cfg.max_delta_chain_depth,
            base_cursor: None,
            failure: None,
            terminal: None,
            missing: false,
            missing_base: false,
            complete: false,
        }
    };
    // A retryable read failure still spent work. Persist its safe checkpoint
    // before returning the original storage refusal to the foreground caller.
    let slice_error = slice_with(store, shards, repo, &mut progress, metrics, None, request)
        .await
        .err();
    if let Some(error) = slice_error.as_ref()
        && error.code() != crate::Code::Unavailable
    {
        return Err(error.clone());
    }
    *publication = Some(Box::new(progress.clone()));
    let encoded = bounded_state(&mut state);
    let state::VerificationV1::Verified {
        publication: Some(retained),
        ..
    } = &state
    else {
        return Err(unavailable());
    };
    progress = (**retained).clone();
    let key = keys::verification(&repo.name, &root);
    let mut batch = Batch::new()
        .require(Precondition::NotAfter(now.saturating_add(10_000)))
        .require(Precondition::Equals(key.clone(), prior))
        .put(key.clone(), encoded);
    if !progress.complete
        && progress.failure.is_none()
        && progress.terminal.is_none()
        && !progress.missing
    {
        let timer = keys::timer(now.saturating_add(1_000), 12, key.as_bytes());
        batch = batch
            .require(Precondition::Absent(timer.clone()))
            .put(timer, Value::new(wanted.to_vec()));
    }
    if metered
        .apply(source, batch)
        .await
        .map_err(|_| unavailable())?
        != BatchOutcome::Committed
    {
        return Err(crate::indexed::pending(1_000));
    }
    if let Some(error) = slice_error {
        return Err(error);
    }
    progress
        .result(advance, now, created, cfg.relay_lag_bound_ms)
        .map(|()| true)
}

/// Why one proof step stopped, typed so classification never reads messages.
enum Step {
    Server(ServerError),
    /// A per-lookup index cap (input limit).
    Lookup,
    /// The retained-evidence item bound (implementation capacity).
    Capacity,
}
impl From<ServerError> for Step {
    fn from(error: ServerError) -> Self {
        Self::Server(error)
    }
}

fn missing() -> ServerError {
    ServerError::unavailable("publication membership missing")
}

async fn one<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    metrics: &dyn crate::Metrics,
) -> Result<u64, Step> {
    let additions = progress.additions.clone();
    let live = PairStore {
        store,
        repo,
        additions: &additions,
        packs: None,
        policy: &Immediate,
    };
    if progress.base_cursor.is_some() {
        return external_base(store, &live, shards, repo, progress, metrics).await;
    }
    if let Some(id) = progress.next_packmap {
        if !progress.chain.insert(id) {
            return Err(Step::Lookup);
        }
        if !progress.additions.contains(&id)
            && !crate::store::read::is_member(&live, shards, repo, &id, None)
                .await
                .map_err(|_| unavailable())?
        {
            return Err(missing().into());
        }
        let (length, prev, packs) = inventory::packlist_facts(store, &id)
            .await
            .map_err(|_| unavailable())?;
        progress.next_packmap = prev;
        progress.dependencies.insert(id);
        progress.dependencies.extend(packs.iter().copied());
        progress.packs.extend(packs);
        return Ok(length);
    }
    let Some(id) = progress.queue.pop_front() else {
        progress.complete = true;
        return Ok(0);
    };
    if !progress.visited.insert(id) {
        return Ok(0);
    }
    let closure = PairStore {
        store,
        repo,
        additions: &progress.additions,
        packs: Some(&progress.packs),
        policy: &Immediate,
    };
    let located = resolve::locate_split(&closure, shards, repo, &[id], metrics)
        .await?
        .remove(&id)
        .ok_or_else(missing)?
        .map_err(|_| Step::Lookup)?
        .ok_or_else(missing)?;
    inventory::seal(store, &located.pack)
        .await
        .map_err(|_| unavailable())?;
    let row = inventory::entry(store, &located.pack, &id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(missing)?;
    if row.canonical_len != located.value.decoded_size || row.kind == 0 || row.kind == 6 {
        return Err(unavailable().into());
    }
    if Some(id) == progress.value.head && !matches!(row.kind, 3 | 4 | 7) {
        return Err(closed().into());
    }
    progress.dependencies.insert(located.pack);
    for n in 0..row.references.pages.len() {
        let children = denial::page(store, &row.references, n).await?;
        for child in children {
            if !progress.visited.contains(&child) && !progress.queue.contains(&child) {
                if progress.visited.len() + progress.queue.len() >= MAX_ADVANCE_ITEMS {
                    return Err(Step::Capacity);
                }
                progress.queue.push_back(child);
            }
        }
    }
    progress.base_cursor = row.base.map(|next| BaseCursor {
        origin: located.pack,
        next,
        depth: 0,
    });
    Ok(row.canonical_len)
}

// Each base is a durable boundary, so a valid maximum-depth chain can span
// several 128-call slices without restarting the entire canonical object.
async fn external_base<S: NamespaceStore>(
    store: &S,
    live: &PairStore<'_, S>,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    metrics: &dyn crate::Metrics,
) -> Result<u64, Step> {
    let cursor = progress.base_cursor.clone().ok_or_else(unavailable)?;
    if cursor.depth >= progress.depth_limit {
        return Err(ServerError::invalid_argument("delta chain too deep").into());
    }
    let selected = resolve::locate_split(live, shards, repo, &[cursor.next], metrics)
        .await?
        .remove(&cursor.next)
        .ok_or_else(missing)?
        .map_err(|_| Step::Lookup)?
        .ok_or_else(missing)?;
    let parent = inventory::entry(store, &selected.pack, &cursor.next)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(missing)?;
    inventory::seal(store, &selected.pack)
        .await
        .map_err(|_| unavailable())?;
    if parent.canonical_len != selected.value.decoded_size || parent.kind == 0 || parent.kind == 6 {
        return Err(unavailable().into());
    }
    if selected.pack != cursor.origin {
        progress.bases.insert(selected.pack);
    }
    progress.base_cursor = parent.base.map(|next| BaseCursor {
        origin: cursor.origin,
        next,
        depth: cursor.depth + 1,
    });
    Ok(parent.canonical_len)
}

struct SliceStore<'a, S> {
    store: &'a S,
    calls: &'a SliceBudget,
    alarm: Option<&'a crate::purge::SliceBudget>,
    stopped: std::sync::atomic::AtomicBool,
}
impl<S> SliceStore<'_, S> {
    fn charge(&self) -> Result<(), StoreError> {
        self.calls.charge()?;
        if let Some(alarm) = self.alarm
            && !alarm.charge(1)
        {
            self.stopped
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(StoreError::unavailable(
                "publication alarm budget exhausted",
            ));
        }
        Ok(())
    }
}
impl<S: NamespaceStore> NamespaceStore for SliceStore<'_, S> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        self.charge()?;
        self.store.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[crate::Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.charge()?;
        self.store.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.charge()?;
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid("publication slice is read-only".into()))
    }
    async fn stats(&self, _: &Partition) -> Result<crate::PartitionStats, StoreError> {
        Err(StoreError::Invalid("publication slice is read-only".into()))
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.charge()?;
        self.store.probe().await
    }
}

async fn slice<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    metrics: &dyn crate::Metrics,
    alarm: Option<&crate::purge::SliceBudget>,
) -> Result<(), ServerError> {
    slice_with(store, shards, repo, progress, metrics, alarm, None).await
}

/// One slice drawing from the foreground request's ledger when it has one.
#[allow(clippy::too_many_lines)] // Typed step outcomes, rollback and the slice's stop reasons.
async fn slice_with<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    metrics: &dyn crate::Metrics,
    alarm: Option<&crate::purge::SliceBudget>,
    request: Option<&SliceBudget>,
) -> Result<(), ServerError> {
    let budget = request.map_or_else(
        || SliceBudget::new(SLICE_CALLS),
        |request| request.child(SLICE_CALLS),
    );
    let remote = SliceStore {
        store,
        calls: &budget,
        alarm,
        stopped: std::sync::atomic::AtomicBool::new(false),
    };
    let mut bytes = 0u64;
    let failure_before = progress.failure;
    while !progress.complete && bytes < SLICE_BYTES {
        // A rollback retains only immutable metadata, never decoded content.
        let before = progress.clone();
        let start = budget.used();
        let result = one(&remote, shards, repo, progress, metrics).await;
        let used = budget.used() - start;
        progress.calls = before.calls.saturating_add(u64::from(used));
        if progress.calls > TOTAL_CALLS {
            let calls = progress.calls;
            *progress = before;
            progress.calls = calls;
            progress.failure = Some(Exhaustion::IndexCalls);
            break;
        }
        match result {
            Ok(length) => {
                if bytes > 0 && bytes.saturating_add(length) > SLICE_BYTES {
                    let calls = progress.calls;
                    *progress = before;
                    progress.calls = calls;
                    break;
                }
                progress.bytes = before.bytes.saturating_add(length);
                if progress.bytes > progress.byte_limit {
                    progress.failure = Some(Exhaustion::DecodeBudget);
                    break;
                }
                bytes = bytes.saturating_add(length);
                if progress.validate().is_err() {
                    *progress = before;
                    progress.failure = Some(Exhaustion::Traversal);
                    break;
                }
            }
            Err(_)
                if budget.remaining() == 0
                    || remote.stopped.load(std::sync::atomic::Ordering::Relaxed) =>
            {
                let calls = progress.calls;
                *progress = before;
                progress.calls = calls;
                // A step that alone outgrows a whole slice is unsupported capacity.
                // A spent request ledger or alarm share only pauses resumable work.
                if start == 0
                    && !remote.stopped.load(std::sync::atomic::Ordering::Relaxed)
                    && !budget.ancestor_refused()
                {
                    progress.failure = Some(Exhaustion::IndexCalls);
                }
                break;
            }
            Err(Step::Lookup) => {
                *progress = before;
                progress.failure = Some(Exhaustion::IndexLookup);
                break;
            }
            Err(Step::Capacity) => {
                *progress = before;
                progress.failure = Some(Exhaustion::Traversal);
                break;
            }
            Err(Step::Server(error))
                if error.public_message() == "publication membership missing" =>
            {
                let calls = progress.calls;
                *progress = before;
                progress.calls = calls;
                progress.missing_base = progress.base_cursor.is_some();
                progress.missing = true;
                break;
            }
            Err(Step::Server(error)) => {
                let calls = progress.calls;
                *progress = before;
                progress.calls = calls;
                progress.terminal = match error.public_message() {
                    "open closure" => Some(TerminalFailure::OpenClosure),
                    "delta chain too deep" => Some(TerminalFailure::DeltaDepth),
                    _ => None,
                };
                if progress.terminal.is_some() {
                    break;
                }
                return Err(error);
            }
        }
        if budget.remaining() < 16 {
            break;
        }
    }
    if failure_before.is_none()
        && let Some(failure) = progress.failure
    {
        let reason = match failure {
            Exhaustion::IndexCalls => "index_calls",
            Exhaustion::Traversal => "retained_items",
            Exhaustion::DecodeBudget => "decode_budget",
            Exhaustion::IndexLookup => "index_lookup",
        };
        metrics.incr(
            crate::telemetry::METRIC_PUBLICATION_LIMIT_REACHED,
            &[("reason", reason)],
            1,
        );
    }
    Ok(())
}

/// Timer 12 also resumes a verified pack's frozen proposed-pair evidence.
pub(crate) async fn fire<S: NamespaceStore, T: NamespaceStore>(
    ctx: &crate::timers::TimerCtx<'_, S>,
    target: &T,
    timer: &crate::timers::DueTimer,
    alarm: Option<&crate::purge::SliceBudget>,
) -> Result<crate::timers::Fired, StoreError> {
    let key = crate::Key::new(timer.reference.clone());
    let Some(keys::ParsedKey::Verification { repo, .. }) = keys::parse(&key) else {
        return Err(StoreError::Corrupt(
            "invalid publication verification timer".into(),
        ));
    };
    let (ns, shards): (_, &dyn ShardMap) = match ctx.partition {
        Partition::Ref { ns, .. } => (ns.clone(), &D34Shards),
        Partition::Namespace(ns) => (ns.clone(), &SinglePartition),
        _ => {
            return Err(StoreError::Corrupt(
                "wrong publication verification partition".into(),
            ));
        }
    };
    let raw = ctx.store.get(ctx.partition, &key).await?;
    let Some(raw) = raw else {
        return Ok(crate::timers::Fired::Done(Batch::new()));
    };
    let mut state = state::decode(&raw)?;
    let state::VerificationV1::Verified {
        publication: Some(progress),
        ..
    } = &mut state
    else {
        return Ok(crate::timers::Fired::Done(Batch::new()));
    };
    if timer.value.as_bytes() != progress.binding
        || progress.complete
        || progress.failure.is_some()
        || progress.terminal.is_some()
        || progress.missing
    {
        return Ok(crate::timers::Fired::Done(Batch::new()));
    }
    let slice_error = slice(
        target,
        shards,
        &RepoId {
            namespace: ns,
            name: repo,
        },
        progress,
        &crate::telemetry::NoopMetrics,
        alarm,
    )
    .await
    .err();
    if let Some(error) = slice_error.as_ref() {
        if error.code() != crate::Code::Unavailable {
            return Err(StoreError::unavailable(
                "publication verification slice failed",
            ));
        }
        tracing::warn!(%error, "publication verification slice retry checkpointed");
    }
    let encoded = bounded_state(&mut state);
    let state::VerificationV1::Verified {
        publication: Some(progress),
        ..
    } = &state
    else {
        return Err(StoreError::Corrupt("missing publication progress".into()));
    };
    let complete = progress.complete
        || progress.failure.is_some()
        || progress.terminal.is_some()
        || progress.missing;
    let batch = Batch::new()
        .require(Precondition::Equals(key.clone(), raw))
        .require(Precondition::NotAfter(ctx.now_ms.saturating_add(10_000)))
        .put(key, encoded);
    Ok(if complete {
        crate::timers::Fired::Done(batch)
    } else {
        crate::timers::Fired::Reschedule {
            due_at_ms: ctx.now_ms.saturating_add(if slice_error.is_some() {
                crate::timers::RETRY_BACKOFF_MS
            } else {
                1_000
            }),
            value: timer.value.clone(),
            batch,
        }
    })
}

#[cfg(test)]
mod tests;
