//! Strong global denial. Serving proof is independent of holder discovery.
use crate::indexed::{
    IndexedConfig,
    budget::{Budgeted, SliceBudget},
};
use crate::pipeline::ShardMap;
use crate::store::{
    BlockEntry, BorrowedStore, ContentIndex, Key, NamespaceStore, Partition, StoreError, Value,
    keys,
};
use crate::telemetry::Metrics;
use crate::{BlobStore, RepoId, ServerError};
use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Independent action. Chunk IDs are the verified canonical manifest's set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAction {
    pub id: Hash,
    pub takedown_id: Hash,
    pub reason: String,
    pub blocked_at_ms: u64,
    pub chunk_ids: Vec<Hash>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionsV2 {
    version: u8,
    actions: Vec<StoredAction>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAction {
    pub action: BlockAction,
    pub chunk_count: u64,
    pub chunk_digest: Hash,
    pub pages: Vec<ChunkPage>,
    pub page_owner: Hash,
    pub page_action: Hash,
    pub pack_scope: Option<Hash>,
    pub pack_digest: Option<Hash>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkPage {
    pub first: Hash,
    pub last: Hash,
    pub count: u32,
    pub digest: Hash,
}
const INDEX_PREFIX: &[u8] = b"b\0\xffdenial-action-descriptors-v2-index\0";
pub fn descriptor_key(object: &Hash) -> Key {
    let mut bytes = INDEX_PREFIX.to_vec();
    bytes.extend_from_slice(object);
    Key::new(bytes)
}
const PAGE_HASHES: usize = crate::store::MAX_VALUE_BYTES / 32;
pub(super) fn chunk_page_key(object: &Hash, action: &Hash, page: u32) -> Key {
    let mut bytes = keys::block(object).as_bytes().to_vec();
    bytes.extend_from_slice(b"\0chunks\0");
    bytes.extend_from_slice(action);
    bytes.extend_from_slice(&page.to_be_bytes());
    Key::new(bytes)
}
/// Immutable same-shard chunk pages precede action activation. A crash only
/// leaves unreachable pages; retries compare exact bytes and preserve identity.
pub async fn stage_action<S: NamespaceStore>(
    store: &S,
    object: &Hash,
    action: &BlockAction,
    now: u64,
) -> Result<StoredAction, StoreError> {
    if action.chunk_ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(corrupt());
    }
    let mut digest = blake3::Hasher::new();
    let mut pages = Vec::new();
    for (page, chunks) in action.chunk_ids.chunks(PAGE_HASHES).enumerate() {
        let bytes = chunks.concat();
        digest.update(&bytes);
        let key = chunk_page_key(
            object,
            &action.id,
            u32::try_from(page).map_err(|_| corrupt())?,
        );
        pages.push(ChunkPage {
            first: chunks[0],
            last: chunks[chunks.len() - 1],
            count: chunks.len() as u32,
            digest: mkit_core::hash::hash(&bytes),
        });
        let value = Value::new(bytes);
        let partition = crate::store::content_shard(object);
        let old = store.get(&partition, &key).await?;
        if let Some(old) = old {
            if old != value {
                return Err(StoreError::Invalid("denial action identity reused".into()));
            }
        } else {
            let batch = crate::Batch::new()
                .require(crate::Precondition::Absent(key.clone()))
                .require(crate::Precondition::NotAfter(
                    now.saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
                ))
                .put(key.clone(), value.clone());
            match store.apply(&partition, batch).await? {
                crate::BatchOutcome::Committed => {}
                _ if store.get(&partition, &key).await?.as_ref() == Some(&value) => {}
                _ => return Err(StoreError::unavailable("denial chunk page race")),
            }
        }
    }
    let header = BlockAction {
        id: action.id,
        takedown_id: action.takedown_id,
        reason: action.reason.clone(),
        blocked_at_ms: action.blocked_at_ms,
        chunk_ids: Vec::new(),
    };
    Ok(StoredAction {
        action: header,
        chunk_count: action.chunk_ids.len() as u64,
        chunk_digest: *digest.finalize().as_bytes(),
        pages,
        page_owner: *object,
        page_action: action.id,
        pack_scope: None,
        pack_digest: None,
    })
}
pub(crate) async fn page<S: NamespaceStore>(
    store: &S,
    row: &StoredAction,
    index: usize,
) -> Result<Vec<Hash>, ServerError> {
    let desc = row.pages.get(index).ok_or_else(unavailable)?;
    let raw = store
        .get(
            &crate::store::content_shard(&row.page_owner),
            &chunk_page_key(
                &row.page_owner,
                &row.page_action,
                u32::try_from(index).map_err(|_| unavailable())?,
            ),
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    if raw.as_bytes().len() != desc.count as usize * 32
        || mkit_core::hash::hash(raw.as_bytes()) != desc.digest
    {
        return Err(unavailable());
    }
    let ids: Vec<Hash> = raw
        .as_bytes()
        .chunks_exact(32)
        .map(|bytes| bytes.try_into().map_err(|_| unavailable()))
        .collect::<Result<_, _>>()?;
    if ids.first() != Some(&desc.first)
        || ids.last() != Some(&desc.last)
        || ids.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(unavailable());
    }
    Ok(ids)
}
pub(super) async fn chunks_intersect<S: NamespaceStore>(
    store: &S,
    _object: &Hash,
    row: &StoredAction,
    ids: &BTreeSet<Hash>,
) -> Result<bool, ServerError> {
    for (index, desc) in row.pages.iter().enumerate() {
        if ids.range(desc.first..=desc.last).next().is_none() {
            continue;
        }
        if page(store, row, index)
            .await?
            .iter()
            .any(|id| ids.contains(id))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Approved subkey; current V1 producers cannot replace independent actions.
pub fn action_key(id: &Hash) -> Key {
    let mut bytes = keys::block(id).as_bytes().to_vec();
    bytes.extend_from_slice(b"\0actions");
    Key::new(bytes)
}
pub fn decode_actions(raw: Option<&Value>) -> Result<Vec<StoredAction>, StoreError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let dto: ActionsV2 = serde_json::from_slice(raw.as_bytes()).map_err(|_| corrupt())?;
    if dto.version != 2
        || dto.actions.is_empty()
        || dto
            .actions
            .windows(2)
            .any(|w| w[0].action.id >= w[1].action.id)
        || dto.actions.iter().any(|a| {
            a.action.reason.is_empty()
                || a.action.reason.len() > 256
                || !a.action.chunk_ids.is_empty()
                || a.pack_scope.is_some() != a.pack_digest.is_some()
                || a.pages
                    .iter()
                    .any(|p| p.count == 0 || p.count as usize > PAGE_HASHES || p.first > p.last)
                || a.pages.windows(2).any(|w| w[0].last >= w[1].first)
                || a.pages.iter().map(|p| u64::from(p.count)).sum::<u64>() != a.chunk_count
        })
    {
        return Err(corrupt());
    }
    Ok(dto.actions)
}
pub fn encode_actions(actions: Vec<StoredAction>) -> Result<Value, StoreError> {
    let bytes = serde_json::to_vec(&ActionsV2 {
        version: 2,
        actions,
    })
    .map_err(|_| corrupt())?;
    if bytes.len() > crate::store::MAX_VALUE_BYTES {
        return Err(StoreError::Full);
    }
    let value = Value::new(bytes);
    decode_actions(Some(&value))?;
    Ok(value)
}
fn corrupt() -> StoreError {
    StoreError::Corrupt("bad denial actions".into())
}
pub fn representative(raw: Option<&Value>) -> Result<Option<BlockEntry>, StoreError> {
    Ok(decode_actions(raw)?
        .first()
        .map(|a| BlockEntry::new(&a.action.reason, a.action.blocked_at_ms)))
}
pub async fn denied<S: NamespaceStore>(store: &S, id: &Hash) -> Result<bool, ServerError> {
    ContentIndex::new(BorrowedStore(store))
        .blocked(id)
        .await
        .map(|entry| entry.is_some())
        .map_err(|_| unavailable())
}
pub async fn require_clear<S: NamespaceStore>(store: &S, id: &Hash) -> Result<(), ServerError> {
    if denied(store, id).await? {
        return Err(blocked());
    }
    Ok(())
}
fn blocked() -> ServerError {
    ServerError::permission_denied("object blocked")
}
fn unavailable() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

/// A bounded proof target: supplied write IDs, or immutable source inventories.
struct Target<'a> {
    ids: &'a BTreeSet<Hash>,
    manifests: Vec<StoredAction>,
    packs: Vec<Hash>,
}
impl Target<'_> {
    async fn intersects<S: NamespaceStore>(
        &self,
        store: &S,
        ids: &[Hash],
    ) -> Result<bool, ServerError> {
        if ids.iter().any(|id| self.ids.contains(id)) {
            return Ok(true);
        }
        let requested: BTreeSet<Hash> = ids.iter().copied().collect();
        for manifest in &self.manifests {
            if chunks_intersect(store, &manifest.page_owner, manifest, &requested).await? {
                return Ok(true);
            }
        }
        for pack in &self.packs {
            let keys: Vec<Key> = ids
                .iter()
                .map(|id| super::inventory::entry_key(pack, id))
                .collect();
            let rows = store
                .get_many(&crate::store::content_shard(pack), &keys)
                .await
                .map_err(|_| unavailable())?;
            if rows.len() != keys.len() {
                return Err(unavailable());
            }
            if rows.iter().any(Option::is_some) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn chunks<S: NamespaceStore>(
        &self,
        store: &S,
        row: &StoredAction,
    ) -> Result<bool, ServerError> {
        for n in 0..row.pages.len() {
            for ids in page(store, row, n).await?.chunks(256) {
                if self.intersects(store, ids).await? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
pub fn legacy_descriptor_key(object: &Hash) -> Key {
    let mut bytes = descriptor_key(object).as_bytes().to_vec();
    bytes.push(0);
    Key::new(bytes)
}
async fn held<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
) -> Result<bool, ServerError> {
    crate::store::index::holds_any(store, shards, repo, &[*id])
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
}
/// One authoritative 4096-shard scan per invocation; continuation reads share
/// the caller's counter. Never reset it across optimistic apply retries.
async fn prove<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    target: &Target<'_>,
) -> Result<(), ServerError> {
    let start = Key::new(INDEX_PREFIX.to_vec());
    let mut end = INDEX_PREFIX.to_vec();
    *end.last_mut().ok_or_else(unavailable)? = 1;
    let end = Key::new(end);
    for prefix in 0..crate::store::INDEX_FANOUT {
        let mut after = None;
        loop {
            let scan = store
                .scan(
                    &Partition::ContentShard(prefix),
                    &start,
                    &end,
                    after.as_ref(),
                    1,
                )
                .await
                .map_err(|_| unavailable())?;
            for (key, raw) in scan.entries {
                let body = key
                    .as_bytes()
                    .strip_prefix(INDEX_PREFIX)
                    .ok_or_else(unavailable)?;
                if body.len() != 32 && !(body.len() == 33 && body[32] == 0) {
                    return Err(unavailable());
                }
                let object: Hash = body[..32].try_into().map_err(|_| unavailable())?;
                if target.intersects(store, &[object]).await? {
                    return Err(blocked());
                }
                if body.len() == 33 {
                    crate::store::codec::decode_block_entry(&raw).map_err(|_| unavailable())?;
                    if held(store, shards, repo, &object).await? {
                        let (_, row) = super::inventory::member(store, shards, repo, &object)
                            .await
                            .map_err(|_| unavailable())?;
                        if row.kind == 5 && target.chunks(store, &row.references).await? {
                            return Err(blocked());
                        }
                    }
                    continue;
                }
                for action in decode_actions(Some(&raw)).map_err(|_| unavailable())? {
                    if let Some(pack) = action.pack_scope {
                        if super::inventory::seal(store, &pack)
                            .await
                            .map_err(|_| unavailable())?
                            != action.pack_digest.ok_or_else(unavailable)?
                        {
                            return Err(unavailable());
                        }
                        let hit =
                            super::inventory::visit(store, &pack, false, |id, row| async move {
                                if target
                                    .intersects(store, &[id])
                                    .await
                                    .map_err(|_| corrupt())?
                                    && super::inventory::is_file(store, &pack, &id).await?
                                {
                                    return Ok(true);
                                }
                                if row.kind == 5
                                    && held(store, shards, repo, &id)
                                        .await
                                        .map_err(|_| corrupt())?
                                    && target
                                        .chunks(store, &row.references)
                                        .await
                                        .map_err(|_| corrupt())?
                                {
                                    return Ok(true);
                                }
                                Ok(false)
                            })
                            .await
                            .map_err(|_| unavailable())?;
                        if hit {
                            return Err(blocked());
                        }
                    } else if action.chunk_count > 0
                        && held(store, shards, repo, &object).await?
                        && target.chunks(store, &action).await?
                    {
                        return Err(blocked());
                    }
                }
            }
            match scan.next {
                Some(next) if after.as_ref() != Some(&next) => after = Some(next),
                Some(_) => return Err(unavailable()),
                None => break,
            }
        }
    }
    for id in target.ids {
        require_clear(store, id).await?;
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub async fn require_repo_clear<B: BlobStore, S: NamespaceStore>(
    _blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &BTreeSet<Hash>,
    _cfg: &IndexedConfig,
    _metrics: &dyn Metrics,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    prove(
        &Budgeted::new(store, budget),
        shards,
        repo,
        &Target {
            ids,
            manifests: Vec::new(),
            packs: Vec::new(),
        },
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub async fn require_repo_clear_budgeted<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &BTreeSet<Hash>,
    cfg: &IndexedConfig,
    metrics: &dyn Metrics,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    require_repo_clear(blobs, store, shards, repo, ids, cfg, metrics, budget).await
}
#[allow(clippy::too_many_arguments)]
pub async fn require_object_clear<B: BlobStore, S: NamespaceStore>(
    _blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
    cfg: &IndexedConfig,
    _metrics: &dyn Metrics,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    let remote = Budgeted::new(store, budget);
    let mut ids = BTreeSet::from([*id]);
    let mut manifests = Vec::new();
    let mut cursor = Some(*id);
    for _ in 0..=cfg.max_delta_chain_depth {
        let Some(id) = cursor else { break };
        let (pack, row) = super::inventory::member(&remote, shards, repo, &id)
            .await
            .map_err(|_| unavailable())?;
        ids.insert(pack);
        if row.kind == 5 {
            manifests.push(row.references);
        }
        cursor = row.base;
        if let Some(base) = cursor {
            if !ids.insert(base) {
                return Err(unavailable());
            }
        }
    }
    if cursor.is_some() {
        return Err(unavailable());
    }
    prove(
        &remote,
        shards,
        repo,
        &Target {
            ids: &ids,
            manifests,
            packs: Vec::new(),
        },
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub async fn require_pack_clear<B: BlobStore, S: NamespaceStore>(
    _blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
    _cfg: &IndexedConfig,
    _metrics: &dyn Metrics,
) -> Result<(), ServerError> {
    let budget = SliceBudget::new(9000);
    let remote = Budgeted::new(store, &budget);
    require_clear(&remote, pack).await?;
    super::inventory::visit(&remote, pack, false, |_, _| async { Ok(false) })
        .await
        .map_err(|_| unavailable())?;
    prove(
        &remote,
        shards,
        repo,
        &Target {
            ids: &BTreeSet::from([*pack]),
            manifests: Vec::new(),
            packs: vec![*pack],
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::D34Shards;
    use crate::store::{
        content_shard,
        index::{IndexEntry, IndexValue},
    };
    use crate::telemetry::NoopMetrics;
    use crate::{Batch, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, RepoName};
    use futures_executor::block_on;
    use std::sync::Arc;

    fn store() -> MemoryKv {
        MemoryKv::with_clock(Arc::new(ManualClock::new(0)))
    }
    fn repo(name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).unwrap(),
        }
    }
    fn action(id: u8, chunks: Vec<Hash>) -> BlockAction {
        BlockAction {
            id: [id; 32],
            takedown_id: [id; 32],
            reason: "legal".into(),
            blocked_at_ms: 1,
            chunk_ids: chunks,
        }
    }
    #[test]
    fn legacy_producer_and_overlapping_actions_cannot_erase_denial() {
        block_on(async {
            let store = store();
            let index = ContentIndex::new(BorrowedStore(&store));
            let object = [7; 32];
            index
                .install_block_action(&object, &action(1, vec![]), 1)
                .await
                .unwrap();
            index
                .install_block_action(&object, &action(2, vec![]), 1)
                .await
                .unwrap();
            index
                .block(&object, &BlockEntry::new("legacy", 2), 2)
                .await
                .unwrap();
            index.unblock(&object, 3).await.unwrap();
            assert!(index.blocked(&object).await.unwrap().is_some());
            let raw = store
                .get(&content_shard(&object), &action_key(&object))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(decode_actions(Some(&raw)).unwrap().len(), 2);
            assert!(
                index
                    .install_block_action(&object, &action(1, vec![]), 4)
                    .await
                    .is_ok()
            );
            let mut changed = action(1, vec![]);
            changed.reason = "other".into();
            assert!(
                index
                    .install_block_action(&object, &changed, 4)
                    .await
                    .is_err()
            );
        })
    }
    #[test]
    fn empty_authoritative_scan_has_measured_bound() {
        block_on(async {
            let store = store();
            let budget = SliceBudget::new(9000);
            require_repo_clear(
                &MemoryBlobStore::default(),
                &store,
                &D34Shards,
                &repo("a"),
                &BTreeSet::from([[8; 32]]),
                &IndexedConfig::default(),
                &NoopMetrics,
                &budget,
            )
            .await
            .unwrap();
            // 4096 descriptor-shard scans plus two strong per-object reads:
            // BorrowedStore inherits get_many's sequential-get default.
            assert_eq!(budget.used(), 4098);
        })
    }
    #[test]
    fn chunk_stop_uses_repository_membership_and_not_global_holders() {
        block_on(async {
            let store = store();
            let manifest = [7; 32];
            let chunk = [8; 32];
            let pack = [9; 32];
            let r = repo("a");
            let index = ContentIndex::new(BorrowedStore(&store));
            index
                .install_block_action(&manifest, &action(1, vec![chunk]), 1)
                .await
                .unwrap();
            let entry = IndexEntry {
                object: manifest,
                value: IndexValue {
                    frame_offset: 8,
                    frame_length: 10,
                    wire_type: 0,
                    decoded_size: 20,
                    chain_depth: 0,
                    delta_base: None,
                },
            };
            let plan = crate::store::index::plan_index_rows_direct(
                &D34Shards,
                &r,
                &content_shard(&manifest),
                &pack,
                &[entry],
                0,
            )
            .unwrap();
            for batch in plan.direct {
                let mut writes = Batch::new();
                for (k, v) in batch.puts {
                    writes = writes.put(k, v)
                }
                store.apply(&batch.target, writes).await.unwrap();
            }
            store
                .apply(
                    &D34Shards.membership(&r, &crate::BlobKey::pack(pack)),
                    Batch::new().put(keys::membership(&r.name, &pack), Value::new(vec![1])),
                )
                .await
                .unwrap();
            let result = require_repo_clear(
                &MemoryBlobStore::default(),
                &store,
                &D34Shards,
                &r,
                &BTreeSet::from([chunk]),
                &IndexedConfig::default(),
                &NoopMetrics,
                &SliceBudget::new(9000),
            )
            .await;
            assert_eq!(result.unwrap_err().public_message(), "object blocked");
            require_repo_clear(
                &MemoryBlobStore::default(),
                &store,
                &D34Shards,
                &repo("other"),
                &BTreeSet::from([chunk]),
                &IndexedConfig::default(),
                &NoopMetrics,
                &SliceBudget::new(9000),
            )
            .await
            .unwrap();
            assert!(!denied(&store, &chunk).await.unwrap());
        })
    }
    #[test]
    fn large_chunk_set_reads_only_selected_verified_page_and_rejects_corruption() {
        block_on(async {
            let store = store();
            let manifest = [7; 32];
            let chunks: Vec<Hash> = (0u32..20_000)
                .map(|i| {
                    let mut id = [0; 32];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id
                })
                .collect();
            let index = ContentIndex::new(BorrowedStore(&store));
            index
                .install_block_action(&manifest, &action(1, chunks.clone()), 1)
                .await
                .unwrap();
            let raw = store
                .get(&content_shard(&manifest), &action_key(&manifest))
                .await
                .unwrap()
                .unwrap();
            let rows = decode_actions(Some(&raw)).unwrap();
            assert_eq!(rows[0].pages.len(), 2);
            let budget = SliceBudget::new(2);
            let counted = Budgeted::new(&store, &budget);
            assert!(
                chunks_intersect(
                    &counted,
                    &manifest,
                    &rows[0],
                    &BTreeSet::from([chunks[18_000]])
                )
                .await
                .unwrap()
            );
            assert_eq!(budget.used(), 1);
            store
                .apply(
                    &content_shard(&manifest),
                    Batch::new().put(
                        chunk_page_key(&manifest, &[1; 32], 1),
                        Value::new(vec![0; 32]),
                    ),
                )
                .await
                .unwrap();
            assert!(
                chunks_intersect(
                    &store,
                    &manifest,
                    &rows[0],
                    &BTreeSet::from([chunks[18_000]])
                )
                .await
                .is_err()
            );
            assert!(index.blocked(&manifest).await.unwrap().is_some());
        })
    }
}
