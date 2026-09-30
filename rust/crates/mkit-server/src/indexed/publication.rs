//! Verify the complete resulting pair, independently of inspector verdicts.
use super::{IndexedConfig, resolve};
use crate::ServerError;
use crate::pipeline::{ShardMap, clearance::PublicationPolicy};
use crate::repo::RepoId;
use crate::store::publication::{Advance, MAX_ADVANCE_ITEMS, Pair};
use crate::store::{
    self, Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, Cursor, Key, NamespaceStore,
    Partition, PartitionStats, RangeScan, ScanPage, StoreCapabilities, StoreError, Value, keys,
};
use crate::telemetry::Metrics;
use futures::StreamExt as _;
use mkit_core::hash::{Hash, hash};
use mkit_core::ops::graph::{ClosureMode, children};
use std::collections::{BTreeSet, VecDeque};

fn closed() -> ServerError {
    ServerError::invalid_argument("open closure")
}
fn capped() -> ServerError {
    ServerError::invalid_argument("object index limit exceeded")
}
fn unavailable() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

// Restrict closure lookup to the exact packmap chain. Newly consumed packs
// qualify before live membership commits; this facade never grants bytes on a
// serving path and still applies the hold gate before accepting any membership.
struct PairStore<'a, S> {
    store: &'a S,
    repo: &'a RepoId,
    additions: &'a [Hash],
    packs: Option<&'a BTreeSet<Hash>>,
    policy: &'a dyn PublicationPolicy,
}
impl<S: NamespaceStore> PairStore<'_, S> {
    fn member(&self, key: &Key, value: Option<Value>) -> Option<Value> {
        if let Some(keys::ParsedKey::Membership { repo, pack_id }) = keys::parse(key) {
            if repo != self.repo.name
                || !self.policy.pack_available(self.repo, &pack_id)
                || self.packs.is_some_and(|packs| !packs.contains(&pack_id))
            {
                return None;
            }
            if self.additions.contains(&pack_id) {
                return Some(Value::default());
            }
            return value.filter(|v| store::publication::Witness::decode(v).is_ok_and(|w| !w.held));
        }
        value
    }
}
impl<S: NamespaceStore> NamespaceStore for PairStore<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        let row = self.store.get(p, k).await?;
        if matches!(keys::parse(k), Some(keys::ParsedKey::Membership { .. }))
            && let Some(raw) = &row
        {
            store::publication::Witness::decode(raw)?;
        }
        Ok(self.member(k, row))
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let rows = self.store.get_many(p, keys).await?;
        if rows.len() != keys.len() {
            return Err(StoreError::Corrupt("short pair membership read".into()));
        }
        // Do not hide malformed witnesses as ordinary absence.
        for (key, row) in keys.iter().zip(&rows) {
            if matches!(
                store::keys::parse(key),
                Some(store::keys::ParsedKey::Membership { .. })
            ) && let Some(raw) = row
            {
                store::publication::Witness::decode(raw)?;
            }
        }
        Ok(keys
            .iter()
            .zip(rows)
            .map(|(k, v)| self.member(k, v))
            .collect())
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.store.scan(partition, start, end, after, limit).await
    }
    async fn scan_many(&self, p: &Partition, r: &[RangeScan]) -> Result<Vec<ScanPage>, StoreError> {
        self.store.scan_many(p, r).await
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid("pair verifier is read-only".into()))
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[allow(clippy::too_many_arguments)]
async fn packlist<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: Hash,
    additions: &[Hash],
    remaining: &mut u64,
) -> Result<mkit_core::transfer::PackListNode, ServerError> {
    if !additions.contains(&id)
        && !store::read::is_member(store, shards, repo, &id, None)
            .await
            .map_err(|_| unavailable())?
    {
        return Err(closed());
    }
    let info = blobs
        .head(&BlobKey::pack(id))
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(closed)?;
    let length = info.len;
    if length > *remaining {
        return Err(capped());
    }
    *remaining -= length;
    let body = blobs
        .get(&BlobKey::pack(id), None)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(closed)?;
    let mut bytes = Vec::new();
    match body {
        BlobBody::Bytes(b) => {
            if b.len() as u64 != length {
                return Err(unavailable());
            }
            bytes.extend_from_slice(&b);
        }
        BlobBody::Stream { len, mut stream } => {
            if len != length {
                return Err(unavailable());
            }
            while let Some(b) = stream.next().await {
                let b = b.map_err(|_| unavailable())?;
                if (bytes.len() as u64).saturating_add(b.len() as u64) > length {
                    return Err(unavailable());
                }
                bytes.extend_from_slice(&b);
            }
        }
    }
    if bytes.len() as u64 != length || hash(&bytes) != id {
        return Err(closed());
    }
    mkit_core::transfer::decode_packlist(&bytes).map_err(|_| closed())
}

/// The server fills dependencies from verified content; policy-supplied lists
/// cannot omit a packmap node, reachable object pack or external delta source.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_inner<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    value: &Pair,
    branch: bool,
    advance: &mut Advance,
    policy: &dyn PublicationPolicy,
    cfg: IndexedConfig,
    metrics: &dyn Metrics,
) -> Result<(), ServerError> {
    if branch && value.head.is_some() && value.packmap.is_none() {
        return Err(closed());
    }
    let live = PairStore {
        store,
        repo,
        additions: &advance.additions,
        packs: None,
        policy,
    };
    let mut chain = BTreeSet::new();
    let mut packs = BTreeSet::new();
    let mut next = value.packmap;
    let mut remaining = cfg.decode_budget;
    while let Some(id) = next {
        if chain.len() + packs.len() >= MAX_ADVANCE_ITEMS || !chain.insert(id) {
            return Err(capped());
        }
        let node = packlist(
            blobs,
            &live,
            shards,
            repo,
            id,
            &advance.additions,
            &mut remaining,
        )
        .await?;
        packs.extend(node.packs);
        if chain.len() + packs.len() > MAX_ADVANCE_ITEMS {
            return Err(capped());
        }
        next = node.prev;
    }
    // Branch pairs cannot use a nonempty head with no reconstructing packmap.
    // For standalone refs the caller supplies no packmap and closure may use
    // any live repository member; dependencies still gate reader publication.
    let restricted = value.packmap.is_some();
    let closure = PairStore {
        store,
        repo,
        additions: &advance.additions,
        packs: restricted.then_some(&packs),
        policy,
    };
    let mut queue = VecDeque::from_iter(value.head);
    let mut visited = BTreeSet::new();
    let mut dependencies = chain;
    dependencies.extend(packs.iter().copied());
    let mut bases = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        if !visited.insert(id) {
            continue;
        }
        if visited.len() > MAX_ADVANCE_ITEMS {
            return Err(capped());
        }
        let located = resolve::locate_split(&closure, shards, repo, &[id], metrics)
            .await?
            .remove(&id)
            .ok_or_else(closed)?
            .map_err(|_| capped())?
            .ok_or_else(closed)?;
        dependencies.insert(located.pack);
        let mut memo = resolve::MemberCache::with_work_budget(256);
        let mut visiting = BTreeSet::new();
        let (bytes, _) = resolve::member_object(
            blobs,
            &live,
            shards,
            repo,
            id,
            located,
            cfg.max_delta_chain_depth,
            remaining,
            &mut memo,
            &mut visiting,
            metrics,
        )
        .await
        .map_err(|_| closed())?;
        remaining = remaining
            .checked_sub(memo.retained_bytes())
            .ok_or_else(capped)?;
        for ((_, pack, _), _) in memo.rows() {
            if *pack != located.pack {
                bases.insert(*pack);
            }
        }
        let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| closed())?;
        if Some(id) == value.head && super::verify::history_parents(&object).is_none() {
            return Err(closed());
        }
        queue.extend(children(&object, ClosureMode::History));
        if dependencies.len() > MAX_ADVANCE_ITEMS || bases.len() > MAX_ADVANCE_ITEMS {
            return Err(capped());
        }
    }
    advance.dependencies = dependencies.into_iter().collect();
    advance.external_bases = bases.into_iter().collect();
    Ok(())
}

/// Verify within a shared metadata/blob-call cap; scheduled Workers retain
/// their other advance work budget. Cap exhaustion is a closed-closure denial.
#[allow(clippy::too_many_arguments)]
pub async fn verify<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    value: &Pair,
    branch: bool,
    advance: &mut Advance,
    policy: &dyn PublicationPolicy,
    cfg: IndexedConfig,
    metrics: &dyn Metrics,
) -> Result<(), ServerError> {
    let budget = super::budget::SliceBudget::new(256);
    let blobs = super::budget::Budgeted::new(blobs, &budget);
    let store = super::budget::Budgeted::new(store, &budget);
    let result = verify_inner(
        &blobs, &store, shards, repo, value, branch, advance, policy, cfg, metrics,
    )
    .await;
    if result.is_err() && budget.remaining() == 0 {
        return Err(capped());
    }
    result
}
