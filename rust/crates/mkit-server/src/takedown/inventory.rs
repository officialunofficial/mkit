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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub version: u8,
    pub kind: u8,
    pub base: Option<Hash>,
    pub references: StoredAction,
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    length: u64,
    count: u64,
    digest: Hash,
    complete: bool,
}
pub fn entry_key(pack: &Hash, id: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory\0", id].concat())
}
fn head_key(pack: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory-head"].concat())
}
fn parent_key(pack: &Hash, id: &Hash) -> Key {
    Key::new([keys::block(pack).as_bytes(), b"\0inventory-parent\0", id].concat())
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
fn add_digest(digest: &mut Hash, id: &Hash, row: &Value) {
    let hash = mkit_core::hash::hash(&[id.as_slice(), row.as_bytes()].concat());
    for (a, b) in digest.iter_mut().zip(hash) {
        *a ^= b;
    }
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
    let p = content_shard(pack);
    let key = entry_key(pack, id);
    if let Some(raw) = store.get(&p, &key).await? {
        let existing: Entry = decode(&raw)?;
        if existing.kind != 0 {
            return Ok(());
        }
    }
    let mut chunks: Vec<Hash> = match object {
        Object::ChunkedBlob(cb) => cb.chunks.clone(),
        Object::Tree(_) => children(object, ClosureMode::History).into_iter().collect(),
        _ => Vec::new(),
    };
    chunks.sort_unstable();
    chunks.dedup();
    let references = denial::stage_action(
        store,
        pack,
        &BlockAction {
            id: *id,
            takedown_id: *pack,
            reason: "inventory".into(),
            blocked_at_ms: 0,
            chunk_ids: chunks,
        },
        now,
    )
    .await?;
    let row = encode(&Entry {
        version: 1,
        kind: object.object_type() as u8,
        base,
        references,
    })?;
    put_entry(store, pack, length, id, row, now).await
}
async fn put_entry<S: NamespaceStore>(
    store: &S,
    pack: &Hash,
    length: u64,
    id: &Hash,
    row: Value,
    now: u64,
) -> Result<(), StoreError> {
    let p = content_shard(pack);
    let key = entry_key(pack, id);
    let existing = store.get(&p, &key).await?;
    if let Some(old) = &existing {
        let prior: Entry = decode(old)?;
        let next: Entry = decode(&row)?;
        if prior.kind != 0 || next.kind == 0 {
            return Ok(());
        }
    }
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
    let mut batch = Batch::new()
        .require(guard(hk.clone(), old))
        .require(guard(key.clone(), existing))
        .require(deadline(now))
        .put(hk, encode(&head)?)
        .put(key, row.clone());
    if matches!(parent.kind, 2 | 5) {
        batch = batch.put(parent_key(pack, id), row);
    }
    if store.apply(&p, batch).await? != BatchOutcome::Committed {
        return Err(StoreError::unavailable("inventory stage contention"));
    }
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
            base: None,
            references: refs,
        })?,
        now,
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
    if store.apply(&p, batch).await? != BatchOutcome::Committed {
        return Err(StoreError::unavailable("inventory seal contention"));
    }
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
    let raw = store
        .get(&content_shard(pack), &entry_key(pack, id))
        .await?;
    let row: Option<Entry> = raw.as_ref().map(decode).transpose()?;
    if let Some(row) = &row {
        if row.version != 1 || row.kind > 7 {
            return Err(bad());
        }
        denial::encode_actions(vec![row.references.clone()])?;
    }
    Ok(row)
}
pub async fn member<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: &Hash,
) -> Result<(Hash, Entry), StoreError> {
    let rows = index::locate_many(store, shards, repo, &[*id]).await?;
    let loc = rows
        .first()
        .and_then(|v| v.as_ref().ok())
        .and_then(|v| *v)
        .ok_or_else(bad)?;
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
    let prefix = if parents {
        b"\0inventory-parent\0".as_slice()
    } else {
        b"\0inventory\0".as_slice()
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
            .scan(&content_shard(pack), &start, &end, after.as_ref(), 32)
            .await?;
        for (key, raw) in page.entries {
            let id: Hash = key
                .as_bytes()
                .strip_prefix(start.as_bytes())
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            let row: Entry = decode(&raw)?;
            if row.version != 1 || row.kind > 7 {
                return Err(bad());
            }
            denial::encode_actions(vec![row.references.clone()])?;
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
    if !parents && (count != head.count || digest != head.digest) {
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
    let chunks = visit(store, pack, false, |_, parent| async move {
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
    visit(store, pack, false, |_, parent| async move {
        if parent.kind != 2 {
            return Ok(false);
        }
        denial::chunks_intersect(store, pack, &parent.references, &BTreeSet::from([*id]))
            .await
            .map_err(|_| bad())
    })
    .await
}
