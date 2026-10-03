//! Pair-bound closure evidence in the existing verified MKPL state row.
//! Immutable sealed inventories replace repeated canonical reconstruction.
use super::{PairStore, capped, closed, unavailable};
use crate::indexed::{IndexedConfig, budget::SliceBudget, resolve, state};
use crate::pipeline::{
    D34Shards, ShardMap, SinglePartition,
    clearance::{Immediate, PublicationPolicy},
};
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
}
impl Exhaustion {
    fn error(self) -> ServerError {
        match self {
            Self::DecodeBudget => ServerError::invalid_argument(resolve::DECODE_BUDGET_MESSAGE),
            Self::IndexCalls | Self::Traversal => limit(),
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

fn is_unbound(prior: &Hash) -> bool {
    *prior == Hash::default()
}

/// An explicit new-work or state limit is a resource limit, never a closure
/// refusal. Slice exhaustion alone never reaches this: it resumes on timer 12.
fn limit() -> ServerError {
    ServerError::resource_exhausted("object index limit exceeded")
}

/// Verified pack state may carry exactly one frozen pair's resumable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Persisted checkpoint flags.
pub struct Progress {
    binding: Hash,
    value: Pair,
    generation: u64,
    /// Digest of the prior publication state this proof was started against;
    /// all zero for a proof written before it existed.
    #[serde(default, skip_serializing_if = "is_unbound")]
    prior: Hash,
    /// Whether verified members outside the consumed packs may stand in for
    /// their closure. A ref with no published value inherits nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    inherit: bool,
    additions: Vec<Hash>,
    next_packmap: Option<Hash>,
    chain: BTreeSet<Hash>,
    packs: BTreeSet<Hash>,
    queue: VecDeque<Hash>,
    /// Objects of the consumed packs whose references were walked.
    visited: BTreeSet<Hash>,
    /// Already-verified repository members that new content references. Their
    /// own facts are reused, so their references are not walked again.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    inherited: BTreeSet<Hash>,
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
        let frozen = frozen(
            &self.value,
            self.generation,
            &self.additions,
            self.byte_limit,
            self.depth_limit,
            self.prior,
        )
        .map_err(|_| StoreError::Corrupt("invalid publication binding".into()))?;
        if hash(&frozen) != self.binding {
            return Err(StoreError::Corrupt("publication binding mismatch".into()));
        }
        if [
            self.chain.len(),
            self.packs.len(),
            self.queue.len(),
            self.visited.len(),
            self.inherited.len(),
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
                    || self.value.head.is_some_and(|h| {
                        !self.visited.contains(&h) && !self.inherited.contains(&h)
                    })
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
    fn frontier(&self) -> Vec<Hash> {
        self.inherited.iter().copied().collect()
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
        p.inherited.clear();
        p.dependencies.clear();
        p.bases.clear();
        p.complete = false;
        p.missing = false;
        p.missing_base = false;
    }
    state::encode(state)
}

// A proof written before the prior-state digest existed bound only the first
// five values; keep decoding it.
fn frozen(
    value: &Pair,
    generation: u64,
    additions: &[Hash],
    byte_limit: u64,
    depth_limit: u32,
    prior: Hash,
) -> Result<Vec<u8>, serde_json::Error> {
    if prior == Hash::default() {
        serde_json::to_vec(&(value, generation, additions, byte_limit, depth_limit))
    } else {
        serde_json::to_vec(&(value, generation, additions, byte_limit, depth_limit, prior))
    }
}

/// Bind the proposed pair, the consumed packs and the digest of the exact prior
/// publication row (pair, sequence, boundary and generation).
fn binding(advance: &Advance, cfg: IndexedConfig, prior: Hash) -> Result<Hash, ServerError> {
    frozen(
        &advance.value,
        advance.generation,
        &advance.additions,
        cfg.decode_budget,
        cfg.max_delta_chain_depth,
        prior,
    )
    .map(|bytes| hash(&bytes))
    .map_err(|_| unavailable())
}

/// The prior publication state a proof starts from.
#[derive(Clone, Copy)]
pub(crate) struct Prior {
    /// Digest of the exact prior publication row.
    pub digest: Hash,
    /// The ref already has a published value whose closure was verified.
    pub inherits: bool,
}

fn fresh(advance: &Advance, cfg: IndexedConfig, prior: Prior, wanted: Hash) -> Progress {
    Progress {
        binding: wanted,
        value: advance.value.clone(),
        generation: advance.generation,
        prior: prior.digest,
        inherit: prior.inherits,
        additions: advance.additions.clone(),
        next_packmap: advance.value.packmap,
        chain: BTreeSet::new(),
        packs: BTreeSet::new(),
        queue: VecDeque::from_iter(advance.value.head),
        visited: BTreeSet::new(),
        inherited: BTreeSet::new(),
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
}

/// First slice may complete inline. Otherwise only verification state and timer
/// are written; no ref, membership, outcome or ticket is accepted/consumed.
///
/// Returns the already-verified members that new content references (the
/// frontier), which the caller still checks against fresh denial state.
///
/// The retained proof holds only immutable facts. Whether a pack may be served
/// is mutable policy, so it is asked again on every call, including one that
/// finds the proof already complete.
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
    (prior, policy): (Prior, &dyn PublicationPolicy),
) -> Result<Vec<Hash>, ServerError> {
    let frontier = prepare_proof(
        store, source, shards, repo, advance, cfg, now, metrics, created, prior,
    )
    .await?;
    if advance
        .dependencies
        .iter()
        .chain(&advance.external_bases)
        .any(|pack| !policy.pack_available(repo, pack))
    {
        return Err(crate::indexed::verify::closure_error(
            now,
            created,
            cfg.relay_lag_bound_ms,
        ));
    }
    Ok(frontier)
}

#[allow(clippy::too_many_arguments)]
async fn prepare_proof<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &mut Advance,
    cfg: IndexedConfig,
    now: u64,
    metrics: &dyn crate::Metrics,
    created: u64,
    prior: Prior,
) -> Result<Vec<Hash>, ServerError> {
    let wanted = binding(advance, cfg, prior.digest)?;
    let root_state = match advance.value.packmap {
        Some(root) => state::read(store, source, &repo.name, &root)
            .await
            .map_err(|_| unavailable())?
            .map(|state| (root, state)),
        None => None,
    };
    // A pair without a packmap, or whose packmap has no verification row to
    // carry a checkpoint, completes inside one slice or is refused.
    let Some((root, (mut state, prior_raw))) = root_state else {
        let mut progress = fresh(advance, cfg, prior, wanted);
        slice(store, shards, repo, &mut progress, metrics, None).await?;
        if !progress.complete
            && progress.failure.is_none()
            && progress.terminal.is_none()
            && !progress.missing
        {
            return Err(limit());
        }
        return progress
            .result(advance, now, created, cfg.relay_lag_bound_ms)
            .map(|()| progress.frontier());
    };
    let state::VerificationV1::Verified { publication, .. } = &mut state else {
        return Err(crate::indexed::pending(1_000));
    };
    if let Some(progress) = publication
        .as_ref()
        .filter(|p| p.binding == wanted && !p.missing)
    {
        return progress
            .result(advance, now, created, cfg.relay_lag_bound_ms)
            .map(|()| progress.frontier());
    }
    let mut progress = if let Some(old) = publication.as_ref().filter(|p| p.binding == wanted) {
        let mut resumed = (**old).clone();
        resumed.missing = false;
        resumed
    } else {
        fresh(advance, cfg, prior, wanted)
    };
    // A retryable read failure still spent work. Persist its safe checkpoint
    // before returning the original storage refusal to the foreground caller.
    let slice_error = slice(store, shards, repo, &mut progress, metrics, None)
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
        .require(Precondition::Equals(key.clone(), prior_raw))
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
    if store
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
        .map(|()| progress.frontier())
}

fn missing() -> ServerError {
    ServerError::unavailable("publication membership missing")
}

// One packmap node: membership, then its sealed length, predecessor and packs.
async fn chain_node<S: NamespaceStore>(
    store: &S,
    live: &PairStore<'_, S>,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    id: Hash,
) -> Result<u64, ServerError> {
    if !progress.chain.insert(id) {
        return Err(capped());
    }
    if !progress.additions.contains(&id)
        && !crate::store::read::is_member(live, shards, repo, &id, None)
            .await
            .map_err(|_| unavailable())?
    {
        return Err(missing());
    }
    let (length, prev, packs) = inventory::packlist_facts(store, &id)
        .await
        .map_err(|_| unavailable())?;
    progress.next_packmap = prev;
    progress.dependencies.insert(id);
    progress.dependencies.extend(packs.iter().copied());
    progress.packs.extend(packs);
    Ok(length)
}

async fn one<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    progress: &mut Progress,
    metrics: &dyn crate::Metrics,
) -> Result<u64, ServerError> {
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
        return chain_node(store, &live, shards, repo, progress, id).await;
    }
    let Some(id) = progress.queue.pop_front() else {
        progress.complete = true;
        return Ok(0);
    };
    if progress.visited.contains(&id) || progress.inherited.contains(&id) {
        return Ok(0);
    }
    // Coverage by the proposed packmap chain applies to every object touched.
    let closure = PairStore {
        store,
        repo,
        additions: &progress.additions,
        packs: progress.value.packmap.is_some().then_some(&progress.packs),
        policy: &Immediate,
    };
    let found = resolve::locate_split(&closure, shards, repo, &[id], metrics)
        .await?
        .remove(&id)
        .ok_or_else(missing)?
        .map_err(|_| capped())?;
    let Some(located) = found else {
        // A member outside the proposed packmap is permanently uncovered; only
        // a miss everywhere may still be membership lag.
        if progress.value.packmap.is_some() {
            let anywhere = PairStore {
                packs: None,
                ..closure
            };
            let member = resolve::locate_split(&anywhere, shards, repo, &[id], metrics)
                .await?
                .remove(&id)
                .is_some_and(|row| matches!(row, Ok(Some(_))));
            if member {
                return Err(closed());
            }
        }
        return Err(missing());
    };
    inventory::seal(store, &located.pack)
        .await
        .map_err(|_| unavailable())?;
    let row = inventory::entry(store, &located.pack, &id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(missing)?;
    if row.canonical_len != located.value.decoded_size || row.kind == 0 || row.kind == 6 {
        return Err(unavailable());
    }
    if Some(id) == progress.value.head && !matches!(row.kind, 3 | 4 | 7) {
        return Err(closed());
    }
    progress.dependencies.insert(located.pack);
    // A member of an earlier pair was verified, with its whole closure, when it
    // was admitted; its sealed facts stand in for walking it again. Only the
    // consumed packs' own objects and references are new content.
    if progress.inherit && !progress.additions.contains(&located.pack) {
        progress.inherited.insert(id);
        return Ok(0);
    }
    progress.visited.insert(id);
    for n in 0..row.references.pages.len() {
        let children = denial::page(store, &row.references, n).await?;
        for child in children {
            if !progress.visited.contains(&child)
                && !progress.inherited.contains(&child)
                && !progress.queue.contains(&child)
            {
                if progress.visited.len() + progress.inherited.len() + progress.queue.len()
                    >= MAX_ADVANCE_ITEMS
                {
                    return Err(capped());
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
) -> Result<u64, ServerError> {
    let cursor = progress.base_cursor.clone().ok_or_else(unavailable)?;
    if cursor.depth >= progress.depth_limit {
        return Err(ServerError::invalid_argument("delta chain too deep"));
    }
    let selected = resolve::locate_split(live, shards, repo, &[cursor.next], metrics)
        .await?
        .remove(&cursor.next)
        .ok_or_else(missing)?
        .map_err(|_| capped())?
        .ok_or_else(missing)?;
    let parent = inventory::entry(store, &selected.pack, &cursor.next)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(missing)?;
    inventory::seal(store, &selected.pack)
        .await
        .map_err(|_| unavailable())?;
    if parent.canonical_len != selected.value.decoded_size || parent.kind == 0 || parent.kind == 6 {
        return Err(unavailable());
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
    let budget = SliceBudget::new(SLICE_CALLS);
    let remote = SliceStore {
        store,
        calls: &budget,
        alarm,
        stopped: std::sync::atomic::AtomicBool::new(false),
    };
    let mut bytes = 0u64;
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
                if start == 0 && !remote.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                    progress.failure = Some(Exhaustion::IndexCalls);
                }
                break;
            }
            Err(error) if error.public_message() == "object index limit exceeded" => {
                *progress = before;
                progress.failure = Some(Exhaustion::Traversal);
                break;
            }
            Err(error) if error.public_message() == "publication membership missing" => {
                let calls = progress.calls;
                *progress = before;
                progress.calls = calls;
                progress.missing_base = progress.base_cursor.is_some();
                progress.missing = true;
                break;
            }
            Err(error) => {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod stored_v050_tests {
    crate::stored_golden::tests!(indexed_publication_resume);
}
