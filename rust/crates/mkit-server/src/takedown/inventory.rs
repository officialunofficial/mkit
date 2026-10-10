//! Immutable typed pack facts, staged during verification and sealed before `vs`.
use super::denial::{self, BlockAction, StoredAction};
use crate::pipeline::ShardMap;
use crate::store::{Key, StoreError, Value, content_shard, index, keys};
use crate::{Batch, BatchOutcome, NamespaceStore, Precondition, RepoId};
use mkit_core::{
    hash::Hash,
    object::Object,
    ops::graph::{ClosureMode, children},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
/// A rejected bounded staging write; no effects were committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StagingFailure {
    #[error("staging planning deadline expired (backend time {backend_now})")]
    Expired { backend_now: u64 },
    #[error("staging CAS contention (precondition {index})")]
    CasContention { index: usize },
}
impl StagingFailure {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Expired { .. } => "expired",
            Self::CasContention { .. } => "cas_contention",
        }
    }
}
pub(crate) fn committed(outcome: &BatchOutcome) -> Result<(), StoreError> {
    match outcome {
        BatchOutcome::Committed => Ok(()),
        BatchOutcome::DeadlinePassed { backend_now } => {
            Err(StoreError::unavailable(StagingFailure::Expired {
                backend_now: *backend_now,
            }))
        }
        BatchOutcome::PreconditionFailed { index, .. } => {
            Err(StoreError::unavailable(StagingFailure::CasContention {
                index: *index,
            }))
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum PlanningTime<'a> {
    Fixed(u64),
    Clock(&'a dyn crate::Clock),
}
impl PlanningTime<'_> {
    pub(super) fn deadline(self) -> Precondition {
        let now = match self {
            Self::Fixed(now) => now,
            Self::Clock(clock) => u64::try_from(clock.now_ms()).unwrap_or(0),
        };
        deadline(now)
    }
}
/// Bound scan values and their temporary base64/JSON transport representation.
pub const SCAN_ROWS: u32 = 8;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub version: u8,
    pub kind: u8,
    pub canonical_len: u64,
    pub logical_len: Option<u64>,
    pub base: Option<Hash>,
    pub references: StoredAction,
}
impl Entry {
    fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1
            || self.kind > 7
            || match self.kind {
                0 => self.canonical_len != 0 || self.logical_len.is_some(),
                1 => {
                    self.canonical_len < 10
                        || self.logical_len != self.canonical_len.checked_sub(10)
                }
                5 => self.canonical_len < 22 || self.logical_len.is_none(),
                _ => self.canonical_len < 6 || self.logical_len.is_some(),
            }
        {
            return Err(bad());
        }
        denial::encode_actions(vec![self.references.clone()])?;
        Ok(())
    }
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    length: u64,
    count: u64,
    parents: u64,
    parent_digest: Hash,
    dependencies: u64,
    dependency_digest: Hash,
    digest: Hash,
    complete: bool,
    packlist: Option<PacklistFacts>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PacklistFacts {
    prev: Option<Hash>,
    packs: Vec<Hash>,
}
/// Bind decoded MKPL facts before the verified inventory seal.
pub async fn stage_packlist<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    prev: Option<Hash>,
    packs: &[Hash],
    now: u64,
) -> Result<(), StoreError> {
    if packs.len()
        > crate::store::index::MAX_LOOKUP_IDS + crate::store::outbox::MAX_TICKETS_PER_ADVANCE
    {
        return Err(bad());
    }
    let p = content_shard(pack);
    let key = head_key(pack);
    let raw = store.get(&p, &key).await?;
    let mut head: Head = raw.as_ref().map(decode).transpose()?.unwrap_or(Head {
        version: 1,
        length,
        ..Head::default()
    });
    let facts = PacklistFacts {
        prev,
        packs: packs.to_vec(),
    };
    if head.version != 1 || head.length != length {
        return Err(bad());
    }
    if let Some(old) = head.packlist {
        return if old == facts { Ok(()) } else { Err(bad()) };
    }
    if head.complete {
        return Err(bad());
    }
    head.packlist = Some(facts);
    committed(
        &store
            .apply(
                &p,
                Batch::new()
                    .require(guard(key.clone(), raw))
                    .require(deadline(now))
                    .put(key, encode(&head)?),
            )
            .await?,
    )?;
    Ok(())
}
/// Canonical source was verified before these immutable facts were sealed.
pub(crate) async fn packlist_facts<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
) -> Result<(u64, Option<Hash>, Vec<Hash>), StoreError> {
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await?
        .ok_or_else(bad)?;
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete {
        return Err(bad());
    }
    let facts = head.packlist.ok_or_else(bad)?;
    if facts.packs.len()
        > crate::store::index::MAX_LOOKUP_IDS + crate::store::outbox::MAX_TICKETS_PER_ADVANCE
    {
        return Err(bad());
    }
    Ok((head.length, facts.prev, facts.packs))
}
/// Immutable facts of a sealed pack inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFacts {
    /// Pack length in bytes.
    pub length: u64,
    /// Rows, including the external-base placeholders still missing
    /// ([`Self::dependencies`] of them).
    pub count: u64,
    /// External delta-base placeholders the pack still lacks.
    pub dependencies: u64,
    /// MKPL facts, when the pack is a packmap node: `prev` and listed packs.
    pub packlist: Option<(Option<Hash>, Vec<Hash>)>,
}
/// Read a sealed inventory's head: one call, no row scan. An absent or
/// unsealed inventory is an error, so a caller never trusts partial facts.
pub async fn sealed_facts<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
) -> Result<SealedFacts, StoreError> {
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await?
        .ok_or_else(bad)?;
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete {
        return Err(bad());
    }
    Ok(SealedFacts {
        length: head.length,
        count: head.count,
        dependencies: head.dependencies,
        packlist: head.packlist.map(|f| (f.prev, f.packs)),
    })
}
#[must_use]
pub fn entry_key(pack: &Hash, id: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory\0", id].concat())
}
#[must_use]
pub fn marker_key(pack: &Hash, id: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory-seal\0", id].concat())
}
fn head_key(pack: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory-head"].concat())
}
fn parent_key(pack: &Hash, id: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory-parent\0", id].concat())
}
fn dependency_key(pack: &Hash, id: &Hash) -> Key {
    Key::new(
        [
            keys::block(pack).as_bytes(),
            b"\0inventory-dependency\0",
            id,
        ]
        .concat(),
    )
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid verified pack inventory".into())
}
fn encode<T: Serialize>(v: &T) -> Result<Value, StoreError> {
    let raw = serde_json::to_vec(v).map_err(|_| bad())?;
    if raw.len() > crate::store::MAX_VALUE_BYTES {
        return Err(StoreError::Full);
    }
    Ok(Value::new(raw))
}
fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, StoreError> {
    serde_json::from_slice(v.as_bytes()).map_err(|_| bad())
}
fn guard(key: Key, raw: Option<Value>) -> Precondition {
    match raw {
        None => Precondition::Absent(key),
        Some(v) => Precondition::Equals(key, v),
    }
}
fn deadline(now: u64) -> Precondition {
    Precondition::NotAfter(now.saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS))
}
fn entry_digest(id: &Hash, row: &Value) -> Hash {
    let mut hash = blake3::Hasher::new();
    hash.update(id);
    hash.update(row.as_bytes());
    *hash.finalize().as_bytes()
}
fn add_digest(digest: &mut Hash, id: &Hash, row: &Value) {
    let hash = entry_digest(id, row);
    for (a, b) in digest.iter_mut().zip(hash) {
        *a ^= b;
    }
}
/// A bounded inventory traversal whose aggregate is checked against the seal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InventoryCursor {
    after: Option<Vec<u8>>,
    count: u64,
    digest: Hash,
}
pub(super) async fn has_seal<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
) -> Result<bool, StoreError> {
    let Some(raw) = store.get(&content_shard(pack), &head_key(pack)).await? else {
        return Ok(false);
    };
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete {
        return Err(bad());
    }
    Ok(true)
}
pub(super) async fn next<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    mut state: InventoryCursor,
) -> Result<(InventoryCursor, Vec<(Hash, Entry)>, bool), StoreError> {
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await?
        .ok_or_else(bad)?;
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete || state.count > head.count {
        return Err(bad());
    }
    let start = Key::new([keys::block(pack).as_bytes(), b"\0inventory\0"].concat());
    let mut end = start.as_bytes().to_vec();
    *end.last_mut().ok_or_else(bad)? = 1;
    let after = state.after.clone().map(crate::Cursor::new);
    let page = store
        .scan(
            &content_shard(pack),
            &start,
            &Key::new(end),
            after.as_ref(),
            SCAN_ROWS,
        )
        .await?;
    let mut entries = Vec::new();
    for (key, raw) in page.entries {
        let id: Hash = key
            .as_bytes()
            .strip_prefix(start.as_bytes())
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        if store
            .get(&content_shard(pack), &marker_key(pack, &id))
            .await?
            .as_ref()
            .map(Value::as_bytes)
            != Some(entry_digest(&id, &raw).as_slice())
        {
            return Err(bad());
        }
        let entry: Entry = decode(&raw)?;
        if entry.version != 1 || entry.kind > 7 {
            return Err(bad());
        }
        denial::encode_actions(vec![entry.references.clone()])?;
        state.count = state.count.checked_add(1).ok_or_else(bad)?;
        add_digest(&mut state.digest, &id, &raw);
        entries.push((id, entry));
    }
    if page
        .next
        .as_ref()
        .is_some_and(|next| after.as_ref() == Some(next))
    {
        return Err(bad());
    }
    state.after = page.next.map(|next| next.as_bytes().to_vec());
    let done = state.after.is_none();
    if state.count > head.count || done && (state.count, state.digest) != (head.count, head.digest)
    {
        return Err(bad());
    }
    Ok((state, entries, done))
}
/// The first occurrence owns an entry, like the write-once object index.
/// Pages are staged first; entry, parent descriptor and running seal share one CAS.
pub async fn stage<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    object: &Object,
    base: Option<Hash>,
    now: u64,
) -> Result<(), StoreError> {
    stage_planned(
        store,
        pack,
        length,
        id,
        object,
        base,
        PlanningTime::Fixed(now),
    )
    .await
}
/// Plan each bounded reference page and entry CAS from the current business clock.
pub(crate) async fn stage_with_clock<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    object: &Object,
    base: Option<Hash>,
    clock: &dyn crate::Clock,
) -> Result<(), StoreError> {
    stage_planned(
        store,
        pack,
        length,
        id,
        object,
        base,
        PlanningTime::Clock(clock),
    )
    .await
}
async fn stage_planned<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    object: &Object,
    base: Option<Hash>,
    time: PlanningTime<'_>,
) -> Result<(), StoreError> {
    let deadline = time.deadline();
    let existing = store
        .get(&content_shard(pack), &entry_key(pack, id))
        .await?;
    if let Some(raw) = &existing {
        let existing: Entry = decode(raw)?;
        if existing.kind != 0 {
            return Ok(());
        }
    }
    let history_refs: Vec<Hash> = children(object, ClosureMode::History).into_iter().collect();
    let chunks = history_refs.as_slice();
    // No page I/O separates a reference-free snapshot from its head read.
    // Paged entries discard this snapshot and refresh their plan after staging.
    let plan = chunks.is_empty().then_some((deadline, existing));
    let (canonical_len, logical_len) = match object {
        Object::Blob(b) => (
            (b.data.len() as u64).checked_add(10).ok_or_else(bad)?,
            Some(b.data.len() as u64),
        ),
        Object::ChunkedBlob(cb) => (
            (cb.chunks.len() as u64)
                .checked_mul(32)
                .and_then(|n| n.checked_add(22))
                .ok_or_else(bad)?,
            Some(cb.total_size),
        ),
        _ => (
            mkit_core::serialize::serialize(object)
                .map_err(|_| bad())?
                .len() as u64,
            None,
        ),
    };
    let references = denial::stage_references_planned(
        store,
        pack,
        &BlockAction {
            id: *id,
            takedown_id: *pack,
            reason: "inventory".into(),
            blocked_at_ms: 0,
            chunk_ids: Vec::new(),
        },
        chunks,
        false,
        time,
    )
    .await?;
    let row = encode(&Entry {
        version: 1,
        kind: object.object_type() as u8,
        canonical_len,
        logical_len,
        base,
        references,
    })?;
    put_entry(store, pack, length, id, row, time, plan).await
}
async fn put_entry<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    row: Value,
    time: PlanningTime<'_>,
    plan: Option<(Precondition, Option<Value>)>,
) -> Result<(), StoreError> {
    let p = content_shard(pack);
    let key = entry_key(pack, id);
    let (deadline, existing) = if let Some(plan) = plan {
        plan
    } else {
        let deadline = time.deadline();
        (deadline, store.get(&p, &key).await?)
    };
    if let Some(old) = &existing {
        let prior: Entry = decode(old)?;
        let next: Entry = decode(&row)?;
        if prior.kind != 0 || next.kind == 0 {
            return Ok(());
        }
    }
    // An upgraded placeholder leaves the dependency range, so that range
    // lists exactly the external delta bases the pack still lacks.
    let upgraded = existing.is_some();
    let hk = head_key(pack);
    let old = store.get(&p, &hk).await?;
    let mut head: Head = old.as_ref().map(decode).transpose()?.unwrap_or(Head {
        version: 1,
        length,
        ..Head::default()
    });
    if head.version != 1 || head.length != length || head.complete {
        return Err(bad());
    }
    if let Some(old) = &existing {
        add_digest(&mut head.digest, id, old);
    } else {
        head.count = head.count.checked_add(1).ok_or_else(bad)?;
    }
    add_digest(&mut head.digest, id, &row);
    let parent: Entry = decode(&row)?;
    if matches!(parent.kind, 2 | 5) {
        head.parents = head.parents.checked_add(1).ok_or_else(bad)?;
        add_digest(&mut head.parent_digest, id, &row);
    }
    if upgraded {
        // `existing` was a placeholder: the checks above returned otherwise.
        head.dependencies = head.dependencies.checked_sub(1).ok_or_else(bad)?;
        if let Some(old) = &existing {
            add_digest(&mut head.dependency_digest, id, old);
        }
    } else if parent.kind == 0 {
        head.dependencies = head.dependencies.checked_add(1).ok_or_else(bad)?;
        add_digest(&mut head.dependency_digest, id, &row);
    }
    let mut batch = Batch::new()
        .require(guard(hk.clone(), old))
        .require(guard(key.clone(), existing))
        .require(deadline)
        .put(hk, encode(&head)?)
        .put(key, row.clone())
        .put(
            marker_key(pack, id),
            Value::new(entry_digest(id, &row).to_vec()),
        );
    if matches!(parent.kind, 2 | 5) {
        batch = batch.put(parent_key(pack, id), row.clone());
    }
    if upgraded {
        batch = batch.delete(dependency_key(pack, id));
    } else if parent.kind == 0 {
        batch = batch.put(dependency_key(pack, id), row);
    }
    committed(&store.apply(&p, batch).await?)?;
    Ok(())
}
pub async fn dependency<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    now: u64,
) -> Result<(), StoreError> {
    let refs = denial::stage_action(
        store,
        pack,
        &BlockAction {
            id: *id,
            takedown_id: *pack,
            reason: "inventory".into(),
            blocked_at_ms: 0,
            chunk_ids: Vec::new(),
        },
        now,
    )
    .await?;
    put_entry(
        store,
        pack,
        length,
        id,
        encode(&Entry {
            version: 1,
            kind: 0,
            canonical_len: 0,
            logical_len: None,
            base: None,
            references: refs,
        })?,
        PlanningTime::Fixed(now),
        None,
    )
    .await
}
/// Source hash validation, complete decoding, extraction and index delivery precede this seal.
pub async fn complete<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    now: u64,
) -> Result<(), StoreError> {
    let p = content_shard(pack);
    let key = head_key(pack);
    let old = store.get(&p, &key).await?;
    let mut head: Head = old.as_ref().map(decode).transpose()?.unwrap_or(Head {
        version: 1,
        length,
        ..Head::default()
    });
    if head.version != 1 || head.length != length {
        return Err(bad());
    }
    if head.complete {
        return Ok(());
    }
    head.complete = true;
    let batch = Batch::new()
        .require(guard(key.clone(), old))
        .require(deadline(now))
        .put(key, encode(&head)?);
    committed(&store.apply(&p, batch).await?)?;
    Ok(())
}
pub async fn seal<S: NamespaceStore>(store: &S, pack: &Hash) -> Result<Hash, StoreError> {
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await?
        .ok_or_else(bad)?;
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete {
        return Err(bad());
    }
    Ok(mkit_core::hash::hash(raw.as_bytes()))
}
pub async fn entry<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    id: &Hash,
) -> Result<Option<Entry>, StoreError> {
    let values = store
        .get_many(
            &content_shard(pack),
            &[entry_key(pack, id), marker_key(pack, id)],
        )
        .await?;
    if values.len() != 2 {
        return Err(bad());
    }
    let raw = values[0].as_ref();
    if let Some(raw) = raw
        && values[1].as_ref().map(Value::as_bytes) != Some(entry_digest(id, raw).as_slice())
    {
        return Err(bad());
    }
    let row: Option<Entry> = raw.map(decode).transpose()?;
    if let Some(row) = &row {
        row.validate()?;
    }
    Ok(row)
}
/// Read sealed facts for already located members. Each partition group is
/// bounded before allocating keys; seals and per-entry digests remain required.
#[cfg(feature = "http-objects")]
pub(crate) async fn located_entries<S: NamespaceStore>(
    store: &S,
    located: &[(Hash, index::LocatedObject)],
) -> Result<std::collections::BTreeMap<Hash, Entry>, StoreError> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<crate::Partition, Vec<(Hash, index::LocatedObject)>> = BTreeMap::new();
    for &(id, location) in located {
        groups
            .entry(content_shard(&location.pack))
            .or_default()
            .push((id, location));
    }
    let mut facts = BTreeMap::new();
    for (partition, entries) in groups {
        for chunk in entries.chunks(16) {
            let packs: BTreeSet<_> = chunk.iter().map(|(_, loc)| loc.pack).collect();
            let mut keys: Vec<_> = packs.iter().map(head_key).collect();
            for (id, loc) in chunk {
                keys.push(entry_key(&loc.pack, id));
                keys.push(marker_key(&loc.pack, id));
            }
            let values = store.get_many(&partition, &keys).await?;
            if values.len() != keys.len() {
                return Err(bad());
            }
            for raw in &values[..packs.len()] {
                let head: Head = decode(raw.as_ref().ok_or_else(bad)?)?;
                if head.version != 1 || !head.complete {
                    return Err(bad());
                }
            }
            for ((id, loc), pair) in chunk.iter().zip(values[packs.len()..].chunks_exact(2)) {
                let raw = pair[0].as_ref().ok_or_else(bad)?;
                if pair[1].as_ref().map(Value::as_bytes) != Some(entry_digest(id, raw).as_slice()) {
                    return Err(bad());
                }
                let row: Entry = decode(raw)?;
                row.validate()?;
                if row.canonical_len != loc.value.decoded_size || row.base != loc.value.delta_base {
                    return Err(bad());
                }
                facts.insert(*id, row);
            }
        }
    }
    Ok(facts)
}
pub async fn member<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
) -> Result<(Hash, Entry), StoreError> {
    member_with_caps(store, shards, repo, id)
        .await
        .map_err(|fail| match fail {
            MemberFail::Capped => bad(),
            MemberFail::Store(error) => error,
        })
}
/// Why a membership lookup failed: a bounded index lookup ran out of rows,
/// pages or membership reads, or an ordinary store/corruption error.
pub(crate) enum MemberFail {
    Capped,
    Store(StoreError),
}
impl From<StoreError> for MemberFail {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
pub(crate) async fn member_with_caps<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
) -> Result<(Hash, Entry), MemberFail> {
    let rows = index::locate_many(store, shards, repo, &[*id]).await?;
    let loc = match rows.first() {
        Some(Ok(Some(loc))) => *loc,
        // TooManyRows on a delta-base hop makes a located target unreconstructable, not absent.
        Some(Err(_)) => return Err(MemberFail::Capped),
        _ => return Err(bad().into()),
    };
    seal(store, &loc.pack).await?;
    Ok((
        loc.pack,
        entry(store, &loc.pack, id).await?.ok_or_else(bad)?,
    ))
}
pub async fn prepare_object<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
    action: BlockAction,
    _now: u64,
) -> Result<StoredAction, StoreError> {
    let (_, row) = member(store, shards, repo, id).await?;
    if !matches!(row.kind, 1 | 5) {
        return Err(StoreError::Invalid(
            "takedown target must be file content".into(),
        ));
    }
    let mut stored = row.references;
    stored.action = action;
    if row.kind != 5 {
        stored.pages.clear();
        stored.chunk_count = 0;
        stored.chunk_digest = mkit_core::hash::hash(&[]);
    }
    Ok(stored)
}
pub async fn prepare_pack<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    pack: &Hash,
    action: BlockAction,
    now: u64,
) -> Result<StoredAction, StoreError> {
    if !crate::store::read::is_member(store, shards, repo, pack, None).await? {
        return Err(bad());
    }
    let digest = seal(store, pack).await?;
    let mut stored = denial::stage_action(store, pack, &action, now).await?;
    stored.pack_scope = Some(*pack);
    stored.pack_digest = Some(digest);
    Ok(stored)
}
/// Stream rows with a bounded page, verifying the complete seal before success.
/// Parent-only traversal is for reference lookup; the complete traversal validates count and digest.
pub async fn visit<S: NamespaceStore, F, Fut>(
    store: &S,
    pack: &Hash,
    parents: bool,
    f: F,
) -> Result<bool, StoreError>
where
    F: FnMut(Hash, Entry) -> Fut,
    Fut: std::future::Future<Output = Result<bool, StoreError>>,
{
    let rows = if parents { Rows::Parents } else { Rows::All };
    visit_rows(store, pack, rows, f).await
}

/// Stream only the external delta-base placeholders (`kind` 0) still missing
/// from the pack, with the same seal check as [`visit`]. The scan costs
/// `ceil(dependencies / SCAN_ROWS) + 1` calls, not a pass over every entry.
pub async fn visit_dependencies<S: NamespaceStore, F, Fut>(
    store: &S,
    pack: &Hash,
    f: F,
) -> Result<bool, StoreError>
where
    F: FnMut(Hash, Entry) -> Fut,
    Fut: std::future::Future<Output = Result<bool, StoreError>>,
{
    visit_rows(store, pack, Rows::Dependencies, f).await
}

/// One page (at most [`SCAN_ROWS`]) of a sealed inventory's parent rows (trees
/// and chunk manifests) after `after`, each verified against its marker. The
/// caller has already checked the seal (`sealed_facts`); unlike [`visit`] this
/// makes no pass over the whole range, so it can resume across slices. Returns
/// the rows and the key to resume from, `None` at the end.
pub async fn parent_page<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    after: Option<Vec<u8>>,
) -> Result<(Vec<(Hash, Entry)>, Option<Vec<u8>>), StoreError> {
    let prefix = Key::new([keys::block(pack).as_bytes(), b"\0inventory-parent\0"].concat());
    let mut end = prefix.as_bytes().to_vec();
    *end.last_mut().ok_or_else(bad)? = 1;
    let after = after.map(crate::Cursor::new);
    let page = store
        .scan(
            &content_shard(pack),
            &prefix,
            &Key::new(end),
            after.as_ref(),
            SCAN_ROWS,
        )
        .await?;
    let markers: Result<Vec<Key>, StoreError> = page
        .entries
        .iter()
        .map(|(key, _)| {
            let id: Hash = key
                .as_bytes()
                .strip_prefix(prefix.as_bytes())
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            Ok(marker_key(pack, &id))
        })
        .collect();
    let markers = store.get_many(&content_shard(pack), &markers?).await?;
    if markers.len() != page.entries.len() {
        return Err(bad());
    }
    let mut rows = Vec::with_capacity(markers.len());
    for ((key, raw), marker) in page.entries.into_iter().zip(markers) {
        let id: Hash = key
            .as_bytes()
            .strip_prefix(prefix.as_bytes())
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        if marker.as_ref().map(Value::as_bytes) != Some(entry_digest(&id, &raw).as_slice()) {
            return Err(bad());
        }
        let row: Entry = decode(&raw)?;
        row.validate()?;
        rows.push((id, row));
    }
    Ok((rows, page.next.map(|next| next.as_bytes().to_vec())))
}

#[derive(Clone, Copy)]
enum Rows {
    All,
    Parents,
    Dependencies,
}

async fn visit_rows<S: NamespaceStore, F, Fut>(
    store: &S,
    pack: &Hash,
    rows: Rows,
    mut f: F,
) -> Result<bool, StoreError>
where
    F: FnMut(Hash, Entry) -> Fut,
    Fut: std::future::Future<Output = Result<bool, StoreError>>,
{
    let raw = store
        .get(&content_shard(pack), &head_key(pack))
        .await?
        .ok_or_else(bad)?;
    let head: Head = decode(&raw)?;
    if head.version != 1 || !head.complete {
        return Err(bad());
    }
    let prefix = match rows {
        Rows::Parents => b"\0inventory-parent\0".as_slice(),
        Rows::Dependencies => b"\0inventory-dependency\0".as_slice(),
        Rows::All => b"\0inventory\0".as_slice(),
    };
    let start = Key::new([keys::block(pack).as_bytes(), prefix].concat());
    let mut end = start.as_bytes().to_vec();
    *end.last_mut().ok_or_else(bad)? = 1;
    let end = Key::new(end);
    let mut after = None;
    let mut count = 0u64;
    let mut digest = [0; 32];
    loop {
        let page = store
            .scan(
                &content_shard(pack),
                &start,
                &end,
                after.as_ref(),
                SCAN_ROWS,
            )
            .await?;
        let marker_keys: Result<Vec<Key>, StoreError> = page
            .entries
            .iter()
            .map(|(key, _)| {
                let id: Hash = key
                    .as_bytes()
                    .strip_prefix(start.as_bytes())
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?;
                Ok(marker_key(pack, &id))
            })
            .collect();
        let markers = store.get_many(&content_shard(pack), &marker_keys?).await?;
        if markers.len() != page.entries.len() {
            return Err(bad());
        }
        for ((key, raw), marker) in page.entries.into_iter().zip(markers) {
            let id: Hash = key
                .as_bytes()
                .strip_prefix(start.as_bytes())
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            if marker.as_ref().map(Value::as_bytes) != Some(entry_digest(&id, &raw).as_slice()) {
                return Err(bad());
            }
            let row: Entry = decode(&raw)?;
            row.validate()?;
            count += 1;
            add_digest(&mut digest, &id, &raw);
            if f(id, row).await? {
                return Ok(true);
            }
        }
        match page.next {
            Some(next) if after.as_ref() != Some(&next) => after = Some(next),
            Some(_) => return Err(bad()),
            None => break,
        }
    }
    let expected = match rows {
        Rows::Parents => (head.parents, head.parent_digest),
        Rows::Dependencies => (head.dependencies, head.dependency_digest),
        Rows::All => (head.count, head.digest),
    };
    if (count, digest) != expected {
        return Err(bad());
    }
    Ok(false)
}
/// A Blob used solely as a chunk is not file content in a whole-pack action.
pub async fn is_file<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    id: &Hash,
) -> Result<bool, StoreError> {
    let Some(row) = entry(store, pack, id).await? else {
        return Ok(false);
    };
    if row.kind == 5 {
        return Ok(true);
    }
    if row.kind != 1 {
        return Ok(false);
    }
    let chunks = visit(store, pack, true, |_, parent| async move {
        if parent.kind != 5 {
            return Ok(false);
        }
        denial::chunks_intersect(store, pack, &parent.references, &BTreeSet::from([*id]))
            .await
            .map_err(|_| bad())
    })
    .await?;
    if !chunks {
        return Ok(true);
    }
    visit(store, pack, true, |_, parent| async move {
        if parent.kind != 2 {
            return Ok(false);
        }
        denial::chunks_intersect(store, pack, &parent.references, &BTreeSet::from([*id]))
            .await
            .map_err(|_| bad())
    })
    .await
}
