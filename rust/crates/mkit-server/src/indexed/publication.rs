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
    published_generation: Option<u64>,
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
            return value.filter(|v| {
                store::publication::Witness::decode(v).is_ok_and(|w| {
                    self.published_generation
                        .map_or(!w.held, |generation| w.visible(false, generation))
                })
            });
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
    mut inspection: Option<&mut super::inspection::InspectionSet>,
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
        published_generation: None,
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
        published_generation: None,
    };
    let published = PairStore {
        store,
        repo,
        additions: &[],
        packs: None,
        policy,
        published_generation: Some(advance.generation),
    };
    let mut queue = VecDeque::from_iter(value.head.map(|id| (id, None)));
    let mut visited = BTreeSet::new();
    let mut dependencies = chain;
    dependencies.extend(packs.iter().copied());
    let mut bases = BTreeSet::new();
    while let Some((id, role)) = queue.pop_front() {
        if let (Some(set), Some(kind)) = (&mut inspection, role) {
            set.role(id, kind);
        }
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
        if let Some(set) = &mut inspection {
            let file = matches!(
                object,
                mkit_core::object::Object::Blob(_) | mkit_core::object::Object::ChunkedBlob(_)
            );
            if file
                && !set.contains(&id)
                && !set.in_added(store, shards, repo, id, located.pack).await?
            {
                let visible = resolve::locate_split(&published, shards, repo, &[id], metrics)
                    .await?
                    .remove(&id)
                    .ok_or_else(closed)?
                    .map_err(|_| capped())?
                    .is_some();
                if !visible {
                    set.reachable_entry(id, bytes.len() as u64, object.object_type() as u8)?;
                }
            }
            if let Some(kind) = role {
                set.role(id, kind);
            }
            set.roles(&object);
        }
        match &object {
            mkit_core::object::Object::Tree(tree) if inspection.is_some() => {
                queue.extend(tree.entries.iter().map(|entry| {
                    (
                        entry.object_hash,
                        (entry.mode != mkit_core::object::EntryMode::Tree)
                            .then_some(super::inspection::Kind::Blob),
                    )
                }));
            }
            mkit_core::object::Object::ChunkedBlob(manifest) if inspection.is_some() => {
                queue.extend(
                    manifest
                        .chunks
                        .iter()
                        .map(|id| (*id, Some(super::inspection::Kind::Chunk))),
                );
            }
            _ => queue.extend(
                children(&object, ClosureMode::History)
                    .into_iter()
                    .map(|id| (id, None)),
            ),
        }
        if dependencies.len() > MAX_ADVANCE_ITEMS || bases.len() > MAX_ADVANCE_ITEMS {
            return Err(capped());
        }
    }
    if let Some(set) = &mut inspection {
        set.complete_added(blobs, store, shards, repo, cfg, metrics)
            .await?;
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
    verify_optional(
        blobs, store, shards, repo, value, branch, advance, policy, cfg, metrics, None,
    )
    .await
}

/// Verify the resulting pair while extending its complete inspected set.
///
/// # Errors
/// Existing closed-closure/index-limit errors; oversized inspection is permanent.
#[allow(clippy::too_many_arguments)]
pub async fn verify_inspected<B: BlobStore, S: NamespaceStore>(
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
    inspection: &mut super::inspection::InspectionSet,
) -> Result<(), ServerError> {
    verify_optional(
        blobs,
        store,
        shards,
        repo,
        value,
        branch,
        advance,
        policy,
        cfg,
        metrics,
        Some(inspection),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn verify_optional<B: BlobStore, S: NamespaceStore>(
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
    inspection: Option<&mut super::inspection::InspectionSet>,
) -> Result<(), ServerError> {
    let budget = super::budget::SliceBudget::new(256);
    let blobs = super::budget::Budgeted::new(blobs, &budget);
    let store = super::budget::Budgeted::new(store, &budget);
    let result = verify_inner(
        &blobs, &store, shards, repo, value, branch, advance, policy, cfg, metrics, inspection,
    )
    .await;
    if result.is_err() && budget.remaining() == 0 {
        return Err(capped());
    }
    result
}

#[cfg(all(test, feature = "memory"))]
mod inspection_tests {
    use super::*;
    use crate::indexed::tests::{repo, source};
    use crate::memory::MemoryKv;
    use crate::pipeline::SinglePartition;
    use crate::rt::BoxFuture;
    use crate::store::{codec, index::IndexValue};
    use crate::telemetry::NoopMetrics;
    use futures_executor::block_on;

    struct Available;
    impl PublicationPolicy for Available {
        fn prepare<'a>(
            &'a self,
            _: &'a crate::Operation,
            value: &'a Pair,
        ) -> BoxFuture<'a, Result<Advance, ServerError>> {
            Box::pin(async move {
                Ok(crate::pipeline::clearance::immediate(
                    value.clone(),
                    [0; 32],
                    vec![],
                ))
            })
        }
        fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
            true
        }
    }

    #[test]
    fn published_lookup_finds_any_published_candidate_after_an_unpublished_one() {
        let repo = repo("published-candidates");
        let store = MemoryKv::default();
        let id = [3; 32];
        let value = IndexValue {
            frame_offset: 12,
            frame_length: 16,
            wire_type: 0,
            decoded_size: 11,
            chain_depth: 0,
            delta_base: None,
        };
        let mut batch = Batch::new();
        for (pack, published) in [([1; 32], false), ([2; 32], true)] {
            batch = batch
                .put(
                    keys::object_index(&repo.name, &id, &pack),
                    codec::encode_object_index(&id, &value).unwrap(),
                )
                .put(
                    keys::membership(&repo.name, &pack),
                    store::publication::Witness {
                        generation: 0,
                        sequence: 1,
                        published,
                        held: false,
                    }
                    .encode(),
                );
        }
        block_on(store.apply(&source(&repo), batch)).unwrap();
        let published = PairStore {
            store: &store,
            repo: &repo,
            additions: &[],
            packs: None,
            policy: &Available,
            published_generation: Some(0),
        };
        let found = block_on(resolve::locate_split(
            &published,
            &SinglePartition,
            &repo,
            &[id],
            &NoopMetrics,
        ))
        .unwrap();
        assert_eq!(found[&id].unwrap().unwrap().pack, [2; 32]);
    }
}
