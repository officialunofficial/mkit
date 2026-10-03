//! Repository flags and their monotonic version share the canonical zero-id object-index partition.
//!
//! Unintegrated groundwork for future async inspection: no pipeline or adapter path writes flags.

use std::collections::BTreeSet;

use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

use super::outbox::guard;
use super::{Batch, BatchOutcome, NamespaceStore, Partition, StoreError, Value, codec, keys};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;

/// Maximum ids per call: 48 record and one version CAS/put pair use 98 of 100 operations.
pub const MAX_FLAG_IDS: usize = 48;
/// Maximum distinct inspection sources retained per object; history is never pruned.
pub const MAX_FLAG_SOURCES: usize = 1024;
const MAX_ATTEMPTS: usize = 16;

/// Stable verdict origin, preserved across delivery retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagSource {
    /// Inspector identity.
    pub inspector: String,
    /// Logical inspection identity, distinct from authentication nonces.
    pub inspection_id: String,
    /// Ref whose committed advance produced the verdict.
    pub ref_name: String,
    /// Positive, per-ref advance sequence.
    pub sequence: u64,
}

/// A retained flag's current authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlagState {
    /// Serving is stopped for this object.
    Flagged,
    /// Administrative review released the stop.
    Released,
}

/// Strict version-one stored flag, including its key binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagV1 {
    /// Flagged object id; must match the storage key.
    pub id: Hash,
    /// Verdict's review reason, at most 4096 bytes.
    pub reason: String,
    /// Stable inspection and advance identity.
    pub source: FlagSource,
    /// Current serving authority.
    pub state: FlagState,
    /// Sorted, distinct BLAKE3 digests of every logical source ever installed.
    pub seen_sources: Vec<Hash>,
}

impl FlagV1 {
    /// Construct the first flagged record with durable replay history.
    /// # Errors Returns [`StoreError::Invalid`] for invalid reason or source fields.
    pub fn new(request: FlagInstall) -> Result<Self, StoreError> {
        if !valid(&request.reason, &request.source) {
            return Err(StoreError::Invalid("invalid inspection flag".into()));
        }
        let seen_sources = vec![source_id(&request.source)];
        Ok(Self {
            id: request.id,
            reason: request.reason,
            source: request.source,
            state: FlagState::Flagged,
            seen_sources,
        })
    }
}

fn source_id(source: &FlagSource) -> Hash {
    mkit_core::hash::hash(&serde_json::to_vec(source).expect("FlagSource is JSON serializable"))
}

fn valid_history(record: &FlagV1) -> bool {
    record.seen_sources.len() <= MAX_FLAG_SOURCES
        && record.seen_sources.windows(2).all(|pair| pair[0] < pair[1])
        && record
            .seen_sources
            .binary_search(&source_id(&record.source))
            .is_ok()
}

fn valid(reason: &str, source: &FlagSource) -> bool {
    let nonempty = |s: &str, max: usize| !s.is_empty() && s.len() <= max && !s.contains('\0');
    nonempty(reason, 4096)
        && nonempty(&source.inspector, 1024)
        && nonempty(&source.inspection_id, 1024)
        && source.ref_name.len() <= 1024
        && crate::refs::is_served_ref_name(&source.ref_name)
        && source.sequence > 0
}

/// Encode a validated flag in the version-one JSON envelope.
/// # Errors Returns [`StoreError::Invalid`] for invalid reason, identity, ref, or sequence.
pub fn encode_flag(record: &FlagV1) -> Result<Value, StoreError> {
    if !valid(&record.reason, &record.source) || !valid_history(record) {
        return Err(StoreError::Invalid("invalid inspection flag".into()));
    }
    let mut bytes = vec![codec::CODEC_V1];
    serde_json::to_writer(&mut bytes, record)
        .map_err(|_| StoreError::Invalid("invalid inspection flag".into()))?;
    Ok(Value::new(bytes))
}

/// Decode strictly; unknown versions, fields, states, and origins fail closed.
/// # Errors Returns [`StoreError::Corrupt`] for malformed or invalid records.
pub fn decode_flag(value: &Value) -> Result<FlagV1, StoreError> {
    let corrupt = || StoreError::Corrupt("invalid inspection flag".into());
    let Some((&codec::CODEC_V1, body)) = value.as_bytes().split_first() else {
        return Err(corrupt());
    };
    let record: FlagV1 = serde_json::from_slice(body).map_err(|_| corrupt())?;
    if !valid(&record.reason, &record.source) || !valid_history(&record) {
        return Err(corrupt());
    }
    Ok(record)
}

/// New flag request. Existing flagged objects retain their original origin.
#[derive(Debug, Clone)]
pub struct FlagInstall {
    /// Object being stopped.
    pub id: Hash,
    /// Verdict's review reason.
    pub reason: String,
    /// Origin used to distinguish replay from deliberate re-inspection.
    pub source: FlagSource,
}

/// Coherent bounded lookup, linearized by a version-only checked apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagLookup {
    /// Flagged subset in the requested order; released records are excluded.
    pub flagged: Vec<FlagV1>,
    /// Repository registry version of this subset.
    pub version: u64,
}

/// Storage authority, not connected to pipeline or serving policy.
#[derive(Debug)]
pub struct InspectionFlags<'a, S: ?Sized> {
    store: &'a S,
    repo: &'a RepoId,
    partition: Partition,
}

impl<'a, S: NamespaceStore + ?Sized> InspectionFlags<'a, S> {
    /// Resolve the canonical repository-index partition.
    #[must_use]
    pub fn new(store: &'a S, shards: &dyn ShardMap, repo: &'a RepoId) -> Self {
        Self {
            store,
            repo,
            partition: shards.object_index(repo, &[0; 32]),
        }
    }

    async fn read_version(&self) -> Result<(Option<Value>, u64), StoreError> {
        let value = self
            .store
            .get(&self.partition, &keys::inspection_version(&self.repo.name))
            .await?;
        let version = value
            .as_ref()
            .map(codec::decode_u64)
            .transpose()?
            .unwrap_or(0);
        if value.is_some() && version == 0 {
            return Err(StoreError::Corrupt(
                "inspection registry version is zero".into(),
            ));
        }
        Ok((value, version))
    }

    async fn records(&self, ids: &[Hash]) -> Result<Vec<Option<Value>>, StoreError> {
        let keys: Vec<_> = ids
            .iter()
            .map(|id| keys::inspection_flag(&self.repo.name, id))
            .collect();
        self.store.get_many(&self.partition, &keys).await
    }

    fn record(id: &Hash, value: Option<&Value>) -> Result<Option<FlagV1>, StoreError> {
        let record = value.map(decode_flag).transpose()?;
        if record.as_ref().is_some_and(|r| r.id != *id) {
            return Err(StoreError::Corrupt(
                "inspection flag key binding mismatch".into(),
            ));
        }
        Ok(record)
    }

    async fn commit(&self, batch: Batch) -> Result<bool, StoreError> {
        batch.validate(&self.store.capabilities())?;
        match self.store.apply(&self.partition, batch).await? {
            BatchOutcome::Committed => Ok(true),
            BatchOutcome::PreconditionFailed { .. } => Ok(false),
            BatchOutcome::DeadlinePassed { .. } => {
                Err(StoreError::Corrupt("unexpected inspection deadline".into()))
            }
        }
    }

    /// Atomically install at most 48 distinct flags; unseen sources advance the version.
    /// Replays remain no-ops across releases; history is bounded at 1024 and never pruned.
    /// # Errors Returns storage, input, corruption, overflow, or CAS contention errors.
    pub async fn install_flags(&self, flags: &[FlagInstall]) -> Result<u64, StoreError> {
        if flags.len() > MAX_FLAG_IDS || flags.iter().any(|f| !valid(&f.reason, &f.source)) {
            return Err(StoreError::Invalid(
                "invalid or oversized inspection flags".into(),
            ));
        }
        let ids: Vec<_> = flags.iter().map(|f| f.id).collect();
        bounded(&ids)?;
        let sources: Vec<_> = flags.iter().map(|f| source_id(&f.source)).collect();
        self.mutate(&ids, |index, prior| {
            let request = &flags[index];
            let Some(prior) = prior else {
                return encode_flag(&FlagV1::new(request.clone())?).map(Some);
            };
            let Err(position) = prior.seen_sources.binary_search(&sources[index]) else {
                return Ok(None);
            };
            if prior.seen_sources.len() == MAX_FLAG_SOURCES {
                return Err(StoreError::Invalid(
                    "inspection flag source history exhausted".into(),
                ));
            }
            let mut next = prior.clone();
            next.seen_sources.insert(position, sources[index]);
            if next.state == FlagState::Released {
                next.reason.clone_from(&request.reason);
                next.source.clone_from(&request.source);
                next.state = FlagState::Flagged;
            }
            encode_flag(&next).map(Some)
        })
        .await
    }

    /// Release this flag while retaining its origin, so delayed redelivery cannot reinstall it.
    /// # Errors Returns storage, corruption, overflow, or CAS contention errors.
    pub async fn release_flag(&self, id: &Hash) -> Result<u64, StoreError> {
        self.mutate(&[*id], |_, prior| {
            let Some(record) = prior.filter(|r| r.state == FlagState::Flagged) else {
                return Ok(None);
            };
            let mut released = record.clone();
            released.state = FlagState::Released;
            encode_flag(&released).map(Some)
        })
        .await
    }

    async fn mutate(
        &self,
        ids: &[Hash],
        replacement: impl Fn(usize, Option<&FlagV1>) -> Result<Option<Value>, StoreError>
        + crate::rt::MaybeSync,
    ) -> Result<u64, StoreError> {
        for _ in 0..MAX_ATTEMPTS {
            let (version_raw, mut version) = self.read_version().await?;
            let values = self.records(ids).await?;
            let version_key = keys::inspection_version(&self.repo.name);
            if version_raw.is_none() && values.iter().any(Option::is_some) {
                if self
                    .commit(Batch::new().require(guard(version_key, None)))
                    .await?
                {
                    return Err(StoreError::Corrupt(
                        "inspection flags without registry version".into(),
                    ));
                }
                continue;
            }
            let mut batch = Batch::new().require(guard(version_key.clone(), version_raw.as_ref()));
            for (index, (id, value)) in ids.iter().zip(&values).enumerate() {
                let record = Self::record(id, value.as_ref())?;
                let key = keys::inspection_flag(&self.repo.name, id);
                batch.preconditions.push(guard(key.clone(), value.as_ref()));
                if let Some(next) = replacement(index, record.as_ref())? {
                    version = version.checked_add(1).ok_or_else(|| {
                        StoreError::Corrupt("inspection registry version overflow".into())
                    })?;
                    batch = batch.put(key, next);
                }
            }
            if !batch.writes.is_empty() {
                batch = batch.put(version_key, codec::encode_u64(version));
            }
            if self.commit(batch).await? {
                return Ok(version);
            }
        }
        Err(contended())
    }

    /// Read at most 48 distinct ids; a version guard validates sequential reads and retries races.
    /// # Errors Returns invalid bounds, storage, corruption, or CAS contention errors.
    pub async fn lookup(&self, ids: &[Hash]) -> Result<FlagLookup, StoreError> {
        bounded(ids)?;
        for _ in 0..MAX_ATTEMPTS {
            let (raw, version) = self.read_version().await?;
            let values = self.records(ids).await?;
            let mut flagged = Vec::new();
            for (id, value) in ids.iter().zip(&values) {
                if let Some(record) =
                    Self::record(id, value.as_ref())?.filter(|r| r.state == FlagState::Flagged)
                {
                    flagged.push(record);
                }
            }
            let batch = Batch::new().require(guard(
                keys::inspection_version(&self.repo.name),
                raw.as_ref(),
            ));
            if self.commit(batch).await? {
                if raw.is_none() && values.iter().any(Option::is_some) {
                    return Err(StoreError::Corrupt(
                        "inspection flags without registry version".into(),
                    ));
                }
                return Ok(FlagLookup { flagged, version });
            }
        }
        Err(contended())
    }

    /// Current version; an untouched repository is version zero.
    /// # Errors Returns storage or corrupt-version errors.
    pub async fn version(&self) -> Result<u64, StoreError> {
        self.read_version().await.map(|(_, version)| version)
    }
}

fn bounded(ids: &[Hash]) -> Result<(), StoreError> {
    if ids.len() > MAX_FLAG_IDS || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(StoreError::Invalid(
            "inspection ids must be distinct and bounded".into(),
        ));
    }
    Ok(())
}

fn contended() -> StoreError {
    StoreError::unavailable(std::io::Error::other("inspection registry CAS retry limit"))
}

#[cfg(test)]
#[path = "inspection_flags_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod stored_v050_tests {
    crate::stored_golden::tests!(store_inspection_flags);
}
