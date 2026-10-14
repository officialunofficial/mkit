//! Bind a D34 publication transaction to its durable projection obligations.

use std::collections::BTreeMap;

use mkit_core::hash::Hash;

use crate::pipeline::{D34Shards, ShardMap};
use crate::repo::RepoId;

use super::publication_fence::{MAX_RELAY_BINDINGS, RelayBinding, Target};

use super::{
    Batch, Partition, Precondition, StoreCapabilities, StoreError, Value, Write, codec, keys,
};

/// A publication transaction and the last required relay for each target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationBatch {
    /// Digest of the original guarded transaction, before fence bookkeeping.
    pub digest: Hash,
    /// Target partition and source outbox sequence, in canonical order.
    pub targets: Vec<(Partition, u64)>,
    /// Every newly allocated row carrying published ref-index effects.
    pub relays: Vec<PublicationRelay>,
}
/// Exact source row selected from the actual guarded publication batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRelay {
    /// Destination included in the encoded row and matched against D34 routing.
    pub target: Partition,
    /// Exact source sequence and encoded-row digest.
    pub binding: RelayBinding,
}
impl PublicationBatch {
    /// Derive complete canonical fence targets from this inspected batch.
    ///
    /// # Errors
    /// Refuses inconsistent, empty or unbounded target message bindings.
    pub fn fence_targets(&self) -> Result<Vec<Target>, StoreError> {
        self.targets
            .iter()
            .map(|(target, sequence)| {
                Target::new(
                    target,
                    *sequence,
                    self.relays
                        .iter()
                        .filter(|row| row.target == *target)
                        .map(|row| row.binding.clone())
                        .collect(),
                )
            })
            .collect()
    }
}

fn invalid() -> StoreError {
    StoreError::Invalid("publication lacks matching projection obligations".into())
}

fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn batch_digest(source: &Partition, batch: &Batch) -> Result<Hash, StoreError> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"mkit.publication-fence-batch.v1\0");
    field(&mut hash, &source.encode()?);
    hash.update(&(batch.preconditions.len() as u64).to_be_bytes());
    for precondition in &batch.preconditions {
        match precondition {
            Precondition::Absent(key) => {
                hash.update(&[0]);
                field(&mut hash, key.as_bytes());
            }
            Precondition::Present(key) => {
                hash.update(&[1]);
                field(&mut hash, key.as_bytes());
            }
            Precondition::Equals(key, value) => {
                hash.update(&[2]);
                field(&mut hash, key.as_bytes());
                field(&mut hash, value.as_bytes());
            }
            Precondition::NotAfter(deadline) => {
                hash.update(&[3]);
                hash.update(&deadline.to_be_bytes());
            }
        }
    }
    hash.update(&(batch.writes.len() as u64).to_be_bytes());
    for write in &batch.writes {
        match write {
            Write::Put(key, value) => {
                hash.update(&[0]);
                field(&mut hash, key.as_bytes());
                field(&mut hash, value.as_bytes());
            }
            Write::Delete(key) => {
                hash.update(&[1]);
                field(&mut hash, key.as_bytes());
            }
        }
    }
    Ok(*hash.finalize().as_bytes())
}

fn published_effects(
    source: &Partition,
    batch: &Batch,
) -> Result<BTreeMap<String, Option<Value>>, StoreError> {
    let mut published: BTreeMap<String, Option<Value>> = BTreeMap::new();
    for write in &batch.writes {
        let (key, value) = match write {
            Write::Put(key, value) => (key, Some(value.clone())),
            Write::Delete(key) => (key, None),
        };
        if let Some(keys::ParsedKey::PublishedRef { repo, name }) = keys::parse(key) {
            let Partition::Ref {
                ns,
                repo: source_repo,
                ..
            } = source
            else {
                return Err(StoreError::Unsupported(
                    "publication fence requires D34".into(),
                ));
            };
            let repository = RepoId {
                namespace: ns.clone(),
                name: repo.clone(),
            };
            if &repo != source_repo || D34Shards.ref_shard(&repository, &name) != *source {
                return Err(invalid());
            }
            if let Some(value) = &value {
                codec::decode_ref_id(value)?;
            }
            published.insert(name, value);
        }
    }
    Ok(published)
}

fn prior_outbox_sequence(batch: &Batch) -> Result<u64, StoreError> {
    let mut previous = None;
    for precondition in &batch.preconditions {
        let observed = match precondition {
            Precondition::Absent(key) if *key == keys::outbox_sequence() => Some(0),
            Precondition::Equals(key, value) if *key == keys::outbox_sequence() => {
                Some(codec::decode_u64(value)?)
            }
            Precondition::Present(key) if *key == keys::outbox_sequence() => {
                return Err(invalid());
            }
            _ => None,
        };
        if let Some(observed) = observed
            && previous.replace(observed).is_some()
        {
            return Err(invalid());
        }
    }
    previous.ok_or_else(invalid)
}

/// Inspect a source transaction without changing its guards or effects.
///
/// Each authoritative published ref must have the same final effect in its
/// routed durable projection relay. Relays may include other work, but that
/// work cannot replace a required ref obligation. A transaction with no
/// published-ref effects returns `None`.
///
/// # Errors
/// A publication outside a D34 ref source, a malformed or misrouted row,
/// or a missing projection obligation is refused.
pub fn publication_batch(
    source: &Partition,
    batch: &Batch,
) -> Result<Option<PublicationBatch>, StoreError> {
    batch.validate(&StoreCapabilities::full())?;
    let published = published_effects(source, batch)?;
    if published.is_empty() {
        return Ok(None);
    }
    let previous = prior_outbox_sequence(batch)?;
    let Partition::Ref { ns, repo, .. } = source else {
        return Err(invalid());
    };
    let repository = RepoId {
        namespace: ns.clone(),
        name: repo.clone(),
    };
    let mut projected: BTreeMap<String, (Option<Value>, Partition, u64)> = BTreeMap::new();
    let mut relays: BTreeMap<u64, Value> = BTreeMap::new();
    let mut allocated = None;
    for write in &batch.writes {
        match write {
            Write::Put(key, value) => {
                if *key == keys::outbox_sequence() {
                    allocated = Some(codec::decode_u64(value)?);
                }
                if let Some(keys::ParsedKey::Relay(sequence)) = keys::parse(key) {
                    relays.insert(sequence, value.clone());
                }
            }
            Write::Delete(key) => {
                if *key == keys::outbox_sequence() {
                    allocated = None;
                }
                if let Some(keys::ParsedKey::Relay(sequence)) = keys::parse(key) {
                    relays.remove(&sequence);
                }
            }
        }
    }
    let mut publication_relays = Vec::new();
    for (sequence, raw) in relays {
        if sequence <= previous || allocated.is_none_or(|last| last <= previous || sequence > last)
        {
            return Err(invalid());
        }
        let relay = codec::decode_relay(&raw)?;
        let mut has_projection = false;
        for (key, value) in relay
            .puts
            .iter()
            .map(|(key, value)| (key, Some(value)))
            .chain(relay.deletes.iter().map(|key| (key, None)))
        {
            if let Some(keys::ParsedKey::PublishedIndex {
                repo: target_repo,
                name,
            }) = keys::parse(key)
            {
                if target_repo != *repo
                    || D34Shards.ref_shard(&repository, &name) != *source
                    || D34Shards.ref_index(&repository, &name) != relay.target
                {
                    return Err(invalid());
                }
                has_projection = true;
                projected.insert(name, (value.cloned(), relay.target.clone(), sequence));
            }
        }
        if has_projection {
            if publication_relays.len() == MAX_RELAY_BINDINGS {
                return Err(invalid());
            }
            publication_relays.push(PublicationRelay {
                target: relay.target,
                binding: RelayBinding::new(sequence, &raw)?,
            });
        }
    }
    let mut targets: BTreeMap<Vec<u8>, (Partition, u64)> = BTreeMap::new();
    for (name, expected) in published {
        let (actual, _, _) = projected.remove(&name).ok_or_else(invalid)?;
        if actual != expected {
            return Err(invalid());
        }
    }
    for relay in &publication_relays {
        let sequence = relay.binding.sequence();
        let entry = targets
            .entry(relay.target.encode()?.to_vec())
            .or_insert((relay.target.clone(), sequence));
        entry.1 = entry.1.max(sequence);
    }
    Ok(Some(PublicationBatch {
        digest: batch_digest(source, batch)?,
        targets: targets.into_values().collect(),
        relays: publication_relays,
    }))
}

#[cfg(test)]
#[path = "publication_fence_plan_tests.rs"]
mod tests;
