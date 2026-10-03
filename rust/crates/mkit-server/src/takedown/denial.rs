//! Strong global denial. Serving proof is independent of holder discovery.
use crate::indexed::{
    IndexedConfig,
    budget::{Budgeted, SliceBudget},
};
use crate::pipeline::ShardMap;
use crate::store::{
    BlockEntry, BorrowedStore, ContentIndex, Key, NamespaceStore, StoreError, Value, keys,
};
use crate::{RepoId, ServerError};
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
    pub sorted_pages: bool,
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
#[must_use]
pub fn descriptor_key(object: &Hash) -> Key {
    let mut bytes = INDEX_PREFIX.to_vec();
    bytes.extend_from_slice(object);
    Key::new(bytes)
}
const PAGE_HASHES: usize = crate::store::MAX_VALUE_BYTES / 32;
#[cfg(test)]
static STAGED_PAGE_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
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
    stage_references(store, object, action, &action.chunk_ids, true, now).await
}
/// Sort only one canonical page at a time; no full manifest-sized copy.
pub(super) async fn stage_references<S: NamespaceStore>(
    store: &S,
    object: &Hash,
    action: &BlockAction,
    ids: &[Hash],
    sorted_pages: bool,
    now: u64,
) -> Result<StoredAction, StoreError> {
    let mut digest = blake3::Hasher::new();
    let mut pages = Vec::new();
    for (page, chunk_ids) in ids.chunks(PAGE_HASHES).enumerate() {
        let mut chunks = chunk_ids.to_vec();
        chunks.sort_unstable();
        chunks.dedup();
        let bytes = chunks.concat();
        #[cfg(test)]
        STAGED_PAGE_PEAK.fetch_max(
            chunks.capacity() * 32 + bytes.capacity(),
            std::sync::atomic::Ordering::Relaxed,
        );
        digest.update(&bytes);
        let key = chunk_page_key(
            object,
            &action.id,
            u32::try_from(page).map_err(|_| corrupt())?,
        );
        pages.push(ChunkPage {
            first: chunks[0],
            last: chunks[chunks.len() - 1],
            count: u32::try_from(chunks.len()).map_err(|_| corrupt())?,
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
        sorted_pages,
        chunk_count: pages.iter().map(|p| u64::from(p.count)).sum(),
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
#[must_use]
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
                || (a.sorted_pages && a.pages.windows(2).any(|w| w[0].last >= w[1].first))
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
const MAX_PROOF_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
struct Target<'a> {
    ids: &'a BTreeSet<Hash>,
    manifests: &'a [StoredAction],
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
        for manifest in self.manifests {
            if chunks_intersect(store, &manifest.page_owner, manifest, &requested).await? {
                return Ok(true);
            }
        }
        for pack in &self.packs {
            let keys: Vec<Key> = ids
                .iter()
                .map(|id| super::inventory::marker_key(pack, id))
                .collect();
            let rows = store
                .get_many(&crate::store::content_shard(pack), &keys)
                .await
                .map_err(|_| unavailable())?;
            if rows.len() != keys.len() {
                return Err(unavailable());
            }
            if rows.iter().flatten().any(|row| row.as_bytes().len() != 32) {
                return Err(unavailable());
            }
            if rows.iter().any(Option::is_some) {
                return Ok(true);
            }
            if super::inventory::visit(store, pack, true, |_, row| {
                let requested = &requested;
                async move {
                    if row.kind != 5 {
                        return Ok(false);
                    }
                    chunks_intersect(store, pack, &row.references, requested)
                        .await
                        .map_err(|_| corrupt())
                }
            })
            .await
            .map_err(|_| unavailable())?
            {
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
        for (n, desc) in row.pages.iter().enumerate() {
            if self.packs.is_empty()
                && self.ids.range(desc.first..=desc.last).next().is_none()
                && !self
                    .manifests
                    .iter()
                    .flat_map(|m| &m.pages)
                    .any(|p| p.first <= desc.last && desc.first <= p.last)
            {
                continue;
            }
            for ids in page(store, row, n).await?.chunks(256) {
                if self.intersects(store, ids).await? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
#[must_use]
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
/// One authoritative sixteen-shard directory walk per proof attempt; continuation reads
/// share the caller's counter, retained across optimistic apply retries.
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
    prove_shards(
        store,
        shards,
        repo,
        target,
        &start,
        &end,
        WRITE_PROOF_CONCURRENCY,
    )
    .await?;
    for id in target.ids {
        require_clear(store, id).await?;
    }
    Ok(())
}
/// Only first descriptor pages are prefetched. Each shard's continuations and
/// nested inventory/chunk proofs retain the existing serial working set.
const SCANNER_PROOF_CONCURRENCY: usize = 6;
// Foreground proof leaves two connections for other request work. First-page
// replies reach EOF before any serial nested proof or another batch starts.
const WRITE_PROOF_CONCURRENCY: usize = 4;
// At most 4 MiB of raw descriptor values, plus bounded key/cursor overhead;
// nested proof allocations remain serial.
const _: () = assert!(SCANNER_PROOF_CONCURRENCY * crate::store::MAX_VALUE_BYTES <= 4 * 1024 * 1024);

async fn prove_shards<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    target: &Target<'_>,
    start: &Key,
    end: &Key,
    concurrency: usize,
) -> Result<(), ServerError> {
    let _ = (start, end);
    let mut directory = super::directory::Walk::start(store, concurrency)
        .await
        .map_err(|_| unavailable())?;
    while let Some(id) = directory.next(store).await.map_err(|_| unavailable())? {
        for (key, raw) in super::directory::descriptors(store, &id)
            .await
            .map_err(|_| unavailable())?
        {
            check_descriptor(store, shards, repo, target, &key, &raw).await?;
        }
    }
    Ok(())
}
async fn check_descriptor<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    target: &Target<'_>,
    key: &Key,
    raw: &Value,
) -> Result<(), ServerError> {
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
        crate::store::codec::decode_block_entry(raw).map_err(|_| unavailable())?;
        if held(store, shards, repo, &object).await? {
            let (_, row) = super::inventory::member(store, shards, repo, &object)
                .await
                .map_err(|_| unavailable())?;
            if row.kind == 5 && target.chunks(store, &row.references).await? {
                return Err(blocked());
            }
        }
        return Ok(());
    }
    for action in decode_actions(Some(raw)).map_err(|_| unavailable())? {
        if let Some(pack) = action.pack_scope {
            if super::inventory::seal(store, &pack)
                .await
                .map_err(|_| unavailable())?
                != action.pack_digest.ok_or_else(unavailable)?
            {
                return Err(unavailable());
            }
            let hit = super::inventory::visit(store, &pack, false, |id, row| async move {
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
    Ok(())
}
pub async fn require_repo_clear<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &BTreeSet<Hash>,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    prove(
        &Budgeted::new(store, budget),
        shards,
        repo,
        &Target {
            ids,
            manifests: &[],
            packs: Vec::new(),
        },
    )
    .await
}
pub async fn require_repo_clear_budgeted<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &BTreeSet<Hash>,
    packs: &[Hash],
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    let remote = Budgeted::new(store, budget);
    for pack in packs {
        super::inventory::visit(&remote, pack, false, |_, _| async { Ok(false) })
            .await
            .map_err(|_| unavailable())?;
    }
    prove(
        &remote,
        shards,
        repo,
        &Target {
            ids,
            manifests: &[],
            packs: packs.to_vec(),
        },
    )
    .await
}
pub async fn require_object_clear<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
    cfg: &IndexedConfig,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    let remote = Budgeted::new(store, budget);
    let context = object_context(&remote, shards, repo, id, cfg).await?;
    prove(&remote, shards, repo, &context.target()).await
}
struct ObjectContext {
    ids: BTreeSet<Hash>,
    manifests: Vec<StoredAction>,
}
impl ObjectContext {
    fn bytes(&self) -> usize {
        let mut bytes = self.ids.len() * 128;
        for m in &self.manifests {
            bytes += std::mem::size_of::<StoredAction>()
                + m.action.reason.capacity()
                + m.pages.capacity() * std::mem::size_of::<ChunkPage>();
        }
        bytes
    }
    fn target(&self) -> Target<'_> {
        Target {
            ids: &self.ids,
            manifests: &self.manifests,
            packs: Vec::new(),
        }
    }
}
async fn object_context<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
    cfg: &IndexedConfig,
) -> Result<ObjectContext, ServerError> {
    let mut context = ObjectContext {
        ids: BTreeSet::from([*id]),
        manifests: Vec::new(),
    };
    let mut cursor = Some(*id);
    for _ in 0..=cfg.max_delta_chain_depth {
        let Some(id) = cursor else { break };
        let (pack, row) = super::inventory::member(store, shards, repo, &id)
            .await
            .map_err(|_| unavailable())?;
        context.ids.insert(pack);
        if row.kind == 5 {
            context.manifests.push(row.references);
            if context.bytes() > MAX_PROOF_CONTEXT_BYTES {
                return Err(unavailable());
            }
        }
        cursor = row.base;
        if let Some(base) = cursor
            && !context.ids.insert(base)
        {
            return Err(unavailable());
        }
    }
    if cursor.is_some() {
        return Err(unavailable());
    }
    Ok(context)
}
#[cfg(feature = "http-objects")]
pub(crate) async fn object_denials<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    requested: &BTreeSet<Hash>,
    cfg: &IndexedConfig,
) -> Result<BTreeSet<Hash>, ServerError> {
    let mut contexts = Vec::new();
    let mut bytes = 0;
    for id in requested {
        let context = object_context(store, shards, repo, id, cfg).await?;
        bytes += context.bytes();
        if bytes > MAX_PROOF_CONTEXT_BYTES {
            return Err(unavailable());
        }
        contexts.push((*id, context));
    }
    let start = Key::new(INDEX_PREFIX.to_vec());
    let mut end = INDEX_PREFIX.to_vec();
    *end.last_mut().ok_or_else(unavailable)? = 1;
    let end = Key::new(end);
    let mut denied = BTreeSet::new();
    let _ = (start, end);
    let mut directory = super::directory::Walk::start(store, WRITE_PROOF_CONCURRENCY)
        .await
        .map_err(|_| unavailable())?;
    while let Some(object) = directory.next(store).await.map_err(|_| unavailable())? {
        for (key, raw) in super::directory::descriptors(store, &object)
            .await
            .map_err(|_| unavailable())?
        {
            for (id, context) in &contexts {
                if denied.contains(id) {
                    continue;
                }
                if let Err(error) =
                    check_descriptor(store, shards, repo, &context.target(), &key, &raw).await
                {
                    if error.public_message() != "object blocked" {
                        return Err(error);
                    }
                    denied.insert(*id);
                }
            }
        }
    }
    for (id, context) in contexts {
        for dependency in &context.ids {
            if self::denied(store, dependency)
                .await
                .map_err(|_| unavailable())?
            {
                denied.insert(id);
            }
        }
    }
    Ok(denied)
}

pub async fn require_pack_clear<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
) -> Result<(), ServerError> {
    require_pack_clear_with_concurrency(store, shards, repo, pack, 1).await
}

/// The scanner's strong global proof, with at most eight first-page reads.
/// Every shard and page is still checked under the same shared call budget.
///
/// # Errors
/// A block or any failed, corrupt, or budget-exhausted proof fails closed.
pub async fn require_pack_clear_for_scanner<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
) -> Result<(), ServerError> {
    require_pack_clear_with_concurrency(store, shards, repo, pack, SCANNER_PROOF_CONCURRENCY).await
}

async fn require_pack_clear_with_concurrency<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
    concurrency: usize,
) -> Result<(), ServerError> {
    let budget = SliceBudget::new(9000);
    let remote = Budgeted::new(store, &budget);
    require_clear(&remote, pack).await?;
    super::inventory::visit(&remote, pack, false, |_, _| async { Ok(false) })
        .await
        .map_err(|_| unavailable())?;
    let start = Key::new(INDEX_PREFIX.to_vec());
    let mut end = INDEX_PREFIX.to_vec();
    *end.last_mut().ok_or_else(unavailable)? = 1;
    let end = Key::new(end);
    let target = Target {
        ids: &BTreeSet::from([*pack]),
        manifests: &[],
        packs: vec![*pack],
    };
    prove_shards(&remote, shards, repo, &target, &start, &end, concurrency).await?;
    for id in target.ids {
        require_clear(&remote, id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::D34Shards;
    use crate::store::{
        BatchOutcome, Cursor, Partition, PartitionStats, ScanPage, StoreCapabilities,
    };
    use crate::store::{
        content_shard,
        index::{IndexEntry, IndexValue},
    };
    use crate::{Batch, ManualClock, MemoryKv, NamespaceKey, RepoName};
    use futures_executor::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScanProbe {
        inner: MemoryKv,
        active: AtomicUsize,
        peak: AtomicUsize,
        scans: AtomicUsize,
        completed: AtomicUsize,
        nested: AtomicUsize,
        fail_prefix: Option<u16>,
        stall: bool,
    }
    impl ScanProbe {
        fn new(fail_prefix: Option<u16>, stall: bool) -> Self {
            Self {
                inner: store(),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                scans: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
                nested: AtomicUsize::new(0),
                fail_prefix,
                stall,
            }
        }
    }
    struct ActiveScan<'a>(&'a AtomicUsize);
    impl Drop for ActiveScan<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl NamespaceStore for ScanProbe {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            assert_eq!(
                self.active.load(Ordering::SeqCst),
                0,
                "nested reads await sibling EOF"
            );
            self.nested.fetch_add(1, Ordering::SeqCst);
            self.inner.get(p, key).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            if start.as_bytes() != super::super::directory::PREFIX {
                assert_eq!(
                    self.active.load(Ordering::SeqCst),
                    0,
                    "nested scan awaits sibling EOF"
                );
                self.nested.fetch_add(1, Ordering::SeqCst);
                return self.inner.scan(p, start, end, after, limit).await;
            }
            assert_eq!(limit, super::super::directory::PAGE_ROWS);
            if after.is_some() {
                assert_eq!(
                    self.active.load(Ordering::SeqCst),
                    0,
                    "continuations await sibling EOF"
                );
            }
            self.scans.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _guard = ActiveScan(&self.active);
            let mut remaining = if matches!(p, Partition::ContentShard(prefix) if Some(*prefix) == self.fail_prefix)
            {
                1
            } else {
                3
            };
            futures::future::poll_fn(|cx| {
                if self.stall {
                    return std::task::Poll::Pending;
                }
                if remaining == 0 {
                    std::task::Poll::Ready(())
                } else {
                    remaining -= 1;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            self.completed.fetch_add(1, Ordering::SeqCst);
            if matches!(p, Partition::ContentShard(prefix) if Some(*prefix) == self.fail_prefix) {
                return Err(StoreError::unavailable("probe shard failure"));
            }
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }
    async fn probe_proof(
        store: &ScanProbe,
        budget: &SliceBudget,
        ids: &BTreeSet<Hash>,
        concurrency: usize,
    ) -> Result<(), ServerError> {
        let mut end = INDEX_PREFIX.to_vec();
        *end.last_mut().unwrap() = 1;
        prove_shards(
            &Budgeted::new(store, budget),
            &D34Shards,
            &repo("probe"),
            &Target {
                ids,
                manifests: &[],
                packs: Vec::new(),
            },
            &Key::new(INDEX_PREFIX.to_vec()),
            &Key::new(end),
            concurrency,
        )
        .await
    }

    #[test]
    fn scanner_proof_checks_all_shards_with_measured_concurrency_and_shared_budget() {
        block_on(async {
            for concurrency in [1, WRITE_PROOF_CONCURRENCY, SCANNER_PROOF_CONCURRENCY] {
                let store = ScanProbe::new(None, false);
                let budget = SliceBudget::new(9000);
                probe_proof(&store, &budget, &BTreeSet::new(), concurrency)
                    .await
                    .unwrap();
                assert_eq!(store.peak.load(Ordering::SeqCst), concurrency);
                assert!(store.peak.load(Ordering::SeqCst) <= 6);
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);
                assert_eq!(budget.used(), 16);
                assert_eq!(store.active.load(Ordering::SeqCst), 0);
            }
        });
    }

    #[test]
    fn scanner_proof_preserves_late_block_failure_and_continuations() {
        block_on(async {
            for concurrency in [1, WRITE_PROOF_CONCURRENCY, SCANNER_PROOF_CONCURRENCY] {
                let store = ScanProbe::new(None, false);
                let blocked_id = [255; 32];
                ContentIndex::new(BorrowedStore(&store.inner))
                    .install_block_action(&blocked_id, &action(1, vec![]), 1)
                    .await
                    .unwrap();
                assert!(matches!(
                    probe_proof(
                        &store,
                        &SliceBudget::new(9000),
                        &BTreeSet::from([blocked_id]),
                        concurrency
                    )
                    .await,
                    Err(error) if error.code() == crate::Code::PermissionDenied
                ));
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);
                assert_eq!(store.active.load(Ordering::SeqCst), 0);

                // Distinct descriptors are read through the final directory shard.
                let mut second_id = blocked_id;
                second_id[31] = 254;
                ContentIndex::new(BorrowedStore(&store.inner))
                    .install_block_action(&second_id, &action(2, vec![]), 1)
                    .await
                    .unwrap();
                store.scans.store(0, Ordering::SeqCst);
                probe_proof(
                    &store,
                    &SliceBudget::new(9000),
                    &BTreeSet::new(),
                    concurrency,
                )
                .await
                .unwrap();
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);

                store
                    .inner
                    .apply(
                        &content_shard(&second_id),
                        Batch::new()
                            .put(descriptor_key(&second_id), Value::new(b"corrupt".to_vec())),
                    )
                    .await
                    .unwrap();
                store.scans.store(0, Ordering::SeqCst);
                assert!(matches!(
                    probe_proof(&store, &SliceBudget::new(9000), &BTreeSet::new(), concurrency).await,
                    Err(error) if error.code() == crate::Code::Unavailable
                ));
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);
                assert_eq!(store.active.load(Ordering::SeqCst), 0);

                let failed =
                    ScanProbe::new(Some(super::super::directory::DIRECTORY_SHARDS - 1), false);
                assert!(matches!(
                    probe_proof(
                        &failed,
                        &SliceBudget::new(9000),
                        &BTreeSet::new(),
                        concurrency
                    )
                    .await,
                    Err(error) if error.code() == crate::Code::Unavailable
                ));
                assert_eq!(failed.scans.load(Ordering::SeqCst), 16);
                assert_eq!(failed.active.load(Ordering::SeqCst), 0);
            }
        });
    }

    #[test]
    fn proof_nested_chunks_wait_for_sibling_eof_and_preserve_valid_results() {
        block_on(async {
            for concurrency in [WRITE_PROOF_CONCURRENCY, SCANNER_PROOF_CONCURRENCY] {
                let store = ScanProbe::new(None, false);
                let manifest = [0; 32];
                let chunk = [8; 32];
                let r = repo("probe");
                ContentIndex::new(BorrowedStore(&store.inner))
                    .install_block_action(&manifest, &action(1, vec![chunk]), 1)
                    .await
                    .unwrap();
                member_row(&store.inner, &r, [9; 32], manifest).await;
                assert!(matches!(probe_proof(&store, &SliceBudget::new(9000),
                    &BTreeSet::from([chunk]), concurrency).await,
                    Err(error) if error.code() == crate::Code::PermissionDenied));
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);
                assert_eq!(store.completed.load(Ordering::SeqCst), 16);
                assert!(store.nested.load(Ordering::SeqCst) > 0);
                assert_eq!(store.active.load(Ordering::SeqCst), 0);
                store.scans.store(0, Ordering::SeqCst);
                let budget = SliceBudget::new(9000);
                probe_proof(&store, &budget, &BTreeSet::from([[7; 32]]), concurrency)
                    .await
                    .unwrap();
                assert_eq!(store.scans.load(Ordering::SeqCst), 16);
                assert!(budget.used() > 16 && budget.used() < 9000);
                assert_eq!(store.active.load(Ordering::SeqCst), 0);
            }
        });
    }

    #[test]
    fn proof_error_waits_for_every_dispatched_reply_before_return_or_retry() {
        block_on(async {
            for concurrency in [WRITE_PROOF_CONCURRENCY, SCANNER_PROOF_CONCURRENCY] {
                let store = ScanProbe::new(Some(0), false);
                let budget = SliceBudget::new(9000);
                for attempt in 1..=2 {
                    assert!(matches!(
                        probe_proof(&store, &budget, &BTreeSet::new(), concurrency).await,
                        Err(error) if error.code() == crate::Code::Unavailable
                    ));
                    let expected = attempt * concurrency;
                    assert_eq!(store.scans.load(Ordering::SeqCst), expected);
                    assert_eq!(store.completed.load(Ordering::SeqCst), expected);
                    assert_eq!(store.active.load(Ordering::SeqCst), 0);
                    assert_eq!(budget.used(), u32::try_from(expected).unwrap());
                }
                assert_eq!(store.peak.load(Ordering::SeqCst), concurrency);
            }
        });
    }

    #[test]
    fn scanner_proof_budget_failure_and_cancellation_drop_outstanding_scans() {
        block_on(async {
            let store = ScanProbe::new(None, false);
            let budget = SliceBudget::new(13);
            assert!(matches!(
                probe_proof(&store, &budget, &BTreeSet::new(), SCANNER_PROOF_CONCURRENCY).await,
                Err(error) if error.code() == crate::Code::Unavailable
            ));
            assert_eq!(budget.used(), 13);
            assert_eq!(store.scans.load(Ordering::SeqCst), 13);
            assert_eq!(store.active.load(Ordering::SeqCst), 0);

            let stalled = ScanProbe::new(None, true);
            let budget = SliceBudget::new(9000);
            let ids = BTreeSet::new();
            let mut proof = Box::pin(probe_proof(
                &stalled,
                &budget,
                &ids,
                SCANNER_PROOF_CONCURRENCY,
            ));
            futures::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(proof.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(
                stalled.active.load(Ordering::SeqCst),
                SCANNER_PROOF_CONCURRENCY
            );
            drop(proof);
            assert_eq!(stalled.active.load(Ordering::SeqCst), 0);
            assert_eq!(
                stalled.scans.load(Ordering::SeqCst),
                SCANNER_PROOF_CONCURRENCY
            );
            assert_eq!(
                budget.used(),
                u32::try_from(SCANNER_PROOF_CONCURRENCY).unwrap()
            );
        });
    }

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
        });
    }
    #[test]
    fn directory_proof_calls_are_sixteen_plus_descriptors_and_continuations() {
        block_on(async {
            for count in [0usize, 7, super::super::directory::PAGE_ROWS as usize + 1] {
                let store = store();
                let index = ContentIndex::new(BorrowedStore(&store));
                for n in 0..count {
                    let mut id = [0; 32];
                    id[30..].copy_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
                    index
                        .install_block_action(&id, &action(1, vec![]), 1)
                        .await
                        .unwrap();
                }
                let budget = SliceBudget::new(9000);
                require_repo_clear(&store, &D34Shards, &repo("a"), &BTreeSet::new(), &budget)
                    .await
                    .unwrap();
                assert_eq!(
                    budget.used(),
                    16 + u32::try_from(count).unwrap()
                        + u32::from(count > super::super::directory::PAGE_ROWS as usize)
                );
            }
        });
    }
    #[test]
    fn empty_authoritative_scan_has_measured_bound() {
        block_on(async {
            let store = store();
            let budget = SliceBudget::new(9000);
            require_repo_clear(
                &store,
                &D34Shards,
                &repo("a"),
                &BTreeSet::from([[8; 32]]),
                &budget,
            )
            .await
            .unwrap();
            // 16 directory-shard scans plus two strong per-object reads:
            // BorrowedStore inherits get_many's sequential-get default.
            assert_eq!(budget.used(), 18);
        });
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
                    writes = writes.put(k, v);
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
                &store,
                &D34Shards,
                &r,
                &BTreeSet::from([chunk]),
                &SliceBudget::new(9000),
            )
            .await;
            assert_eq!(result.unwrap_err().public_message(), "object blocked");
            require_repo_clear(
                &store,
                &D34Shards,
                &repo("other"),
                &BTreeSet::from([chunk]),
                &SliceBudget::new(9000),
            )
            .await
            .unwrap();
            assert!(!denied(&store, &chunk).await.unwrap());
        });
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
        });
    }
    async fn member_row(store: &MemoryKv, repo: &RepoId, pack: Hash, id: Hash) {
        let value = IndexValue {
            frame_offset: 1,
            frame_length: 1,
            wire_type: 0,
            decoded_size: 1,
            chain_depth: 0,
            delta_base: None,
        };
        let plan = crate::store::index::plan_index_rows_direct(
            &D34Shards,
            repo,
            &D34Shards.ref_shard(repo, "refs/heads/main"),
            &pack,
            &[IndexEntry { object: id, value }],
            1,
        )
        .unwrap();
        for batch in plan.direct {
            let mut writes = Batch::new();
            for (k, v) in batch.puts {
                writes = writes.put(k, v);
            }
            store.apply(&batch.target, writes).await.unwrap();
        }
        store
            .apply(
                &D34Shards.membership(repo, &crate::BlobKey::pack(pack)),
                Batch::new().put(keys::membership(&repo.name, &pack), Value::new(vec![1])),
            )
            .await
            .unwrap();
    }
    #[test]
    fn million_chunk_manifest_stages_and_proves_with_bounded_pages() {
        use mkit_core::object::{ChunkedBlob, Object};
        block_on(async {
            let store = store();
            let repo = repo("large");
            let pack = [90; 32];
            let chunks: Vec<Hash> = (0u32..1_000_000)
                .rev()
                .map(|n| {
                    let mut id = [0; 32];
                    id[..4].copy_from_slice(&n.to_be_bytes());
                    id
                })
                .collect();
            let object = Object::ChunkedBlob(ChunkedBlob {
                total_size: 65_536_000_000,
                chunk_size: 65_536,
                chunks,
            });
            // This is the core's maximum accepted count, not a reduced server geometry.
            let wire = mkit_core::serialize::serialize(&object).unwrap();
            assert_eq!(mkit_core::serialize::deserialize(&wire).unwrap(), object);
            drop(wire);
            let id = object.id().unwrap();
            super::super::inventory::stage(&store, &pack, 1, &id, &object, None, 1)
                .await
                .unwrap();
            super::super::inventory::complete(&store, &pack, 1, 1)
                .await
                .unwrap();
            let row = super::super::inventory::entry(&store, &pack, &id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.references.chunk_count, 1_000_000);
            assert_eq!(
                row.references.pages.len(),
                1_000_000usize.div_ceil(PAGE_HASHES)
            );
            assert!(!row.references.sorted_pages);
            assert!(
                STAGED_PAGE_PEAK.load(std::sync::atomic::Ordering::Relaxed)
                    <= 2 * crate::store::MAX_VALUE_BYTES
            );
            assert!(row.references.pages.capacity() * std::mem::size_of::<ChunkPage>() < 32 * 1024);
            member_row(&store, &repo, pack, id).await;
            let budget = SliceBudget::new(9000);
            require_object_clear(
                &store,
                &D34Shards,
                &repo,
                &id,
                &IndexedConfig::default(),
                &budget,
            )
            .await
            .unwrap();
            assert!(budget.used() < 4200, "{}", budget.used());
            // A separate held blocked manifest shares a chunk in the LAST canonical page.
            let Object::ChunkedBlob(manifest) = &object else {
                unreachable!()
            };
            let shared = *manifest.chunks.last().unwrap();
            let blocked_id = [91; 32];
            member_row(&store, &repo, pack, blocked_id).await;
            ContentIndex::new(BorrowedStore(&store))
                .install_block_action(&blocked_id, &action(92, vec![shared]), 1)
                .await
                .unwrap();
            let budget = SliceBudget::new(9000);
            let denied = require_object_clear(
                &store,
                &D34Shards,
                &repo,
                &id,
                &IndexedConfig::default(),
                &budget,
            )
            .await
            .unwrap_err();
            assert_eq!(denied.public_message(), "object blocked");
            assert!(budget.used() < 4200, "{}", budget.used());
        });
    }
    #[test]
    fn legacy_hold_release_keeps_chunk_denial_and_unblock_removes_it() {
        use mkit_core::object::{ChunkedBlob, Object};
        block_on(async {
            let store = store();
            let repo = repo("legacy-context");
            let pack = [81; 32];
            let id = [82; 32];
            let chunk = [83; 32];
            super::super::inventory::stage(
                &store,
                &pack,
                1,
                &id,
                &Object::ChunkedBlob(ChunkedBlob {
                    total_size: 1,
                    chunk_size: 0,
                    chunks: vec![chunk],
                }),
                None,
                1,
            )
            .await
            .unwrap();
            super::super::inventory::complete(&store, &pack, 1, 1)
                .await
                .unwrap();
            member_row(&store, &repo, pack, id).await;
            let index = ContentIndex::new(BorrowedStore(&store));
            index
                .block(&id, &BlockEntry::new("policy", 1), 1)
                .await
                .unwrap();
            index.release_hold(&id, &[84; 32], 1).await.unwrap();
            let result = require_repo_clear(
                &store,
                &D34Shards,
                &repo,
                &BTreeSet::from([chunk]),
                &SliceBudget::new(9000),
            )
            .await
            .unwrap_err();
            assert_eq!(result.public_message(), "object blocked");
            index.unblock(&id, 1).await.unwrap();
            require_repo_clear(
                &store,
                &D34Shards,
                &repo,
                &BTreeSet::from([chunk]),
                &SliceBudget::new(9000),
            )
            .await
            .unwrap();
        });
    }
    #[test]
    fn inventory_row_corruption_cannot_change_manifest_type() {
        use mkit_core::object::{ChunkedBlob, Object};
        block_on(async {
            let store = store();
            let repo = repo("corrupt");
            let pack = [71; 32];
            let id = [72; 32];
            super::super::inventory::stage(
                &store,
                &pack,
                1,
                &id,
                &Object::ChunkedBlob(ChunkedBlob {
                    total_size: 1,
                    chunk_size: 0,
                    chunks: vec![[73; 32]],
                }),
                None,
                1,
            )
            .await
            .unwrap();
            super::super::inventory::complete(&store, &pack, 1, 1)
                .await
                .unwrap();
            member_row(&store, &repo, pack, id).await;
            let mut row = super::super::inventory::entry(&store, &pack, &id)
                .await
                .unwrap()
                .unwrap();
            row.kind = 1;
            store
                .apply(
                    &content_shard(&pack),
                    Batch::new().put(
                        super::super::inventory::entry_key(&pack, &id),
                        Value::new(serde_json::to_vec(&row).unwrap()),
                    ),
                )
                .await
                .unwrap();
            assert!(
                super::super::inventory::member(&store, &D34Shards, &repo, &id)
                    .await
                    .is_err()
            );
        });
    }
}

#[cfg(test)]
#[path = "denial_v050_tests.rs"]
mod stored_v050_tests;
