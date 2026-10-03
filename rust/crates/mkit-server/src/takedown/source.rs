//! Bounded repository-member selection before canonical chain reconstruction.
use super::acquisition::Profile;
use crate::pipeline::ShardMap;
use crate::store::{
    StoreError, codec,
    index::{self, LocatedObject},
    keys,
};
use crate::{Batch, BlobKey, Cursor, Key, NamespaceStore, Partition, Precondition, RepoId, Value};
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    after: Vec<u8>,
    pages: u32,
    rows: u32,
    partitions: BTreeSet<Hash>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frame {
    pub id: Hash,
    pub pack: Hash,
    pub index: Vec<u8>,
}
impl Frame {
    pub(crate) fn encode_row(&self) -> Result<Value, StoreError> {
        codec::decode_object_index(&self.id, &Value::new(self.index.clone()))?;
        Ok(Value::new(
            [&self.id[..], &self.pack[..], &self.index].concat(),
        ))
    }
    fn located(&self) -> Result<LocatedObject, StoreError> {
        Ok(LocatedObject {
            pack: self.pack,
            value: codec::decode_object_index(&self.id, &Value::new(self.index.clone()))?,
        })
    }
}
/// Strict selected-row codec, retaining the existing canonical index validation.
pub(crate) fn decode_frame(raw: &Value) -> Result<(Hash, LocatedObject), StoreError> {
    let bytes = raw.as_bytes();
    if !matches!(bytes.len(), 95 | 127) {
        return Err(bad());
    }
    let id = bytes[..32].try_into().map_err(|_| bad())?;
    let pack = bytes[32..64].try_into().map_err(|_| bad())?;
    let value = codec::decode_object_index(&id, &Value::new(bytes[64..].to_vec()))?;
    Ok((id, LocatedObject { pack, value }))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub next: Option<Hash>,
    pub level: u32,
    pub previous: Option<Frame>,
    lookup: Lookup,
}
impl Checkpoint {
    pub(crate) fn new(target: Hash) -> Self {
        Self {
            next: Some(target),
            level: 0,
            previous: None,
            lookup: Lookup::default(),
        }
    }
}
pub(crate) struct Step {
    pub checkpoint: Checkpoint,
    pub batch: Batch,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid preservation source checkpoint".into())
}
fn capped() -> StoreError {
    StoreError::unavailable("preservation source lookup capped")
}
fn limits(profile: &Profile, frame: LocatedObject) -> Result<(), StoreError> {
    if frame.value.frame_length > profile.limits.max_frame_bytes
        || frame.value.decoded_size > profile.limits.max_decoded_bytes
        || frame.value.chain_depth > profile.chain_depth
    {
        return Err(capped());
    }
    Ok(())
}
/// Select at most eight candidates; commit frame rows and checkpoint together.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn step<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    prefix: &Key,
    profile: &Profile,
    mut checkpoint: Checkpoint,
) -> Result<Step, StoreError> {
    if checkpoint.level > profile.chain_depth {
        return Err(bad());
    }
    let Some(id) = checkpoint.next else {
        let previous = checkpoint.previous.as_ref().ok_or_else(bad)?;
        if previous.located()?.value.delta_base.is_some() {
            return Err(bad());
        }
        return Ok(Step {
            checkpoint,
            batch: Batch::new(),
        });
    };
    let lookup = &mut checkpoint.lookup;
    if lookup.after.len() > 4096
        || lookup.rows >= 4096
        || lookup.pages.saturating_add(lookup.rows / 128) >= 512
        || lookup.partitions.len() > index::MAX_LOOKUP_MEMBERSHIP_READS
    {
        return Err(bad());
    }
    let mut selected = None;
    let partition = shards.object_index(repo, &id);
    if let Some(previous) = &checkpoint.previous {
        let previous = previous.located()?;
        if previous.value.delta_base != Some(id) || checkpoint.level == 0 {
            return Err(bad());
        }
        if lookup.rows == 0 && lookup.pages == 0 {
            let member = keys::membership(&repo.name, &previous.pack);
            let owner = shards.membership(repo, &BlobKey::pack(previous.pack));
            let same = keys::object_index(&repo.name, &id, &previous.pack);
            if store.get(&owner, &member).await?.is_some()
                && let Some(raw) = store.get(&partition, &same).await?
            {
                let value = codec::decode_object_index(&id, &raw)?;
                if value.frame_offset < previous.value.frame_offset {
                    selected = Some(LocatedObject {
                        pack: previous.pack,
                        value,
                    });
                }
            }
        }
    } else if checkpoint.level != 0 {
        return Err(bad());
    }
    if selected.is_none() {
        let (start, end) = keys::object_index_range(&repo.name, &id);
        let after = (!lookup.after.is_empty()).then(|| Cursor::new(lookup.after.clone()));
        let maximum = (4096 - lookup.rows).min(8);
        let page = store
            .scan(&partition, &start, &end, after.as_ref(), maximum)
            .await?;
        if page.entries.len() > usize::try_from(maximum).map_err(|_| bad())? {
            return Err(bad());
        }
        lookup.pages += u32::from(page.entries.is_empty() && page.next.is_some());
        lookup.rows += u32::try_from(page.entries.len()).map_err(|_| bad())?;
        let mut groups: BTreeMap<Partition, Vec<Hash>> = BTreeMap::new();
        let mut ordered = Vec::new();
        let mut cap = false;
        for (key, value) in page.entries {
            let Some(keys::ParsedKey::ObjectIndex {
                repo: found,
                object,
                pack_id,
            }) = keys::parse(&key)
            else {
                return Err(bad());
            };
            if found != repo.name || object != id {
                return Err(bad());
            }
            let partition = shards.membership(repo, &BlobKey::pack(pack_id));
            let digest = hash(&partition.encode()?);
            if !lookup.partitions.contains(&digest)
                && lookup.partitions.len() == index::MAX_LOOKUP_MEMBERSHIP_READS
            {
                cap = true;
                break;
            }
            lookup.partitions.insert(digest);
            ordered.push((pack_id, value));
            groups.entry(partition).or_default().push(pack_id);
        }
        let mut members = BTreeSet::new();
        for (partition, packs) in groups {
            let keys: Vec<_> = packs
                .iter()
                .map(|pack| keys::membership(&repo.name, pack))
                .collect();
            let values = store.get_many(&partition, &keys).await?;
            if values.len() != packs.len() {
                return Err(bad());
            }
            for (pack, value) in packs.into_iter().zip(values) {
                if value.is_some() {
                    members.insert(pack);
                }
            }
        }
        for (pack, raw) in ordered {
            if members.contains(&pack) {
                selected = Some(LocatedObject {
                    pack,
                    value: codec::decode_object_index(&id, &raw)?,
                });
                break;
            }
        }
        if selected.is_none() {
            if cap || lookup.rows >= 4096 || lookup.pages.saturating_add(lookup.rows / 128) >= 512 {
                return Err(capped());
            }
            let next = page
                .next
                .ok_or_else(|| StoreError::unavailable("preservation source unavailable"))?;
            lookup.after = next.into_bytes().to_vec();
            return Ok(Step {
                checkpoint,
                batch: Batch::new(),
            });
        }
    }
    let selected = selected.ok_or_else(bad)?;
    limits(profile, selected)?;
    if selected.value.delta_base.is_some() && checkpoint.level == profile.chain_depth {
        return Err(capped());
    }
    let frame = Frame {
        id,
        pack: selected.pack,
        index: codec::encode_object_index(&id, &selected.value)?
            .as_bytes()
            .to_vec(),
    };
    let row = Key::new([prefix.as_bytes(), &checkpoint.level.to_be_bytes()].concat());
    let batch = Batch::new()
        .require(Precondition::Absent(row.clone()))
        .put(row, frame.encode_row()?);
    checkpoint.next = selected.value.delta_base;
    checkpoint.previous = Some(frame);
    checkpoint.lookup = Lookup::default();
    if checkpoint.next.is_some() {
        checkpoint.level += 1;
    }
    Ok(Step { checkpoint, batch })
}

#[cfg(all(test, feature = "memory"))]
#[path = "source_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod stored_v050_tests {
    crate::stored_golden::tests!(takedown_source);
}
