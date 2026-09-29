//! Repository-isolated external delta resolution from member index rows.

use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::{
    codec,
    index::{self, IndexValue, LocatedObject, LookupError, ObjectLookup},
    keys,
};
use crate::telemetry::{METRIC_INDEX_LOOKUP_CAPPED, Metrics};
use crate::{BlobBody, BlobKey, BlobStore, BoxFuture, ByteRange, NamespaceStore, ServerError};
use futures::StreamExt as _;
use mkit_core::hash::Hash;
use mkit_core::pack::{DecodeLimits, DeltaBaseSource, PackError, decode_frame_with};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn unavailable() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

fn budget_exceeded() -> ServerError {
    ServerError::invalid_argument("pack exceeds indexed decode budget")
}

/// A membership miss needs the consuming ticket's lag window; a cap is
/// permanent even inside that window.
#[derive(Debug)]
pub enum ResolveFailure {
    Missing,
    Capped,
    Other(ServerError),
}

impl From<ServerError> for ResolveFailure {
    fn from(error: ServerError) -> Self {
        Self::Other(error)
    }
}

impl ResolveFailure {
    #[must_use]
    pub fn public_error(self, now: u64, created: u64, bound: u64) -> ServerError {
        match self {
            Self::Missing => missing_base(now, created, bound),
            Self::Capped => {
                ServerError::failed_precondition("delta base not available in this repository")
            }
            Self::Other(error) => error,
        }
    }
}

/// Whether a ticket still lies inside the §9.4 repository-membership window.
#[must_use]
pub fn lagged(now_ms: u64, created_at_ms: u64, bound_ms: u64) -> bool {
    now_ms.saturating_sub(created_at_ms) < bound_ms
}

/// Exact error for an unresolved base, independent of global blob existence.
#[must_use]
pub fn missing_base(now_ms: u64, created_at_ms: u64, bound_ms: u64) -> ServerError {
    if lagged(now_ms, created_at_ms, bound_ms) {
        ServerError::unavailable("repository membership not yet visible")
    } else {
        ServerError::failed_precondition("delta base not available in this repository")
    }
}

fn cap_reason(cap: LookupError) -> &'static str {
    match cap {
        LookupError::TooManyRows => "rows",
        LookupError::TooManyPages => "pages",
        LookupError::TooManyMembershipReads => "membership_reads",
    }
}

/// Split retryable capped batch lookups to one id, preserving only
/// repository-scoped answers. A final capped id is returned for the caller's
/// own error mapping.
pub async fn locate_split<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
    metrics: &dyn Metrics,
) -> Result<BTreeMap<Hash, ObjectLookup>, ServerError> {
    locate_split_inner(store, shards, repo, ids, Some(metrics)).await
}

/// Speculatively locate syntactic bases in 256-id batches. The caller reports
/// a cap only if the decoder later requests that id as an external base.
pub async fn locate_split_quiet<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<BTreeMap<Hash, ObjectLookup>, ServerError> {
    locate_split_inner(store, shards, repo, ids, None).await
}

async fn locate_split_inner<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
    metrics: Option<&dyn Metrics>,
) -> Result<BTreeMap<Hash, ObjectLookup>, ServerError> {
    let mut todo: Vec<Vec<Hash>> = ids
        .chunks(index::MAX_LOOKUP_IDS)
        .map(<[Hash]>::to_vec)
        .collect();
    let mut found = BTreeMap::new();
    while let Some(chunk) = todo.pop() {
        let answers = index::locate_many(store, shards, repo, &chunk)
            .await
            .map_err(|_| unavailable())?;
        let split = chunk.len() > 1
            && answers.iter().any(|answer| {
                matches!(
                    answer,
                    Err(LookupError::TooManyPages | LookupError::TooManyMembershipReads)
                )
            });
        if split {
            let mid = chunk.len() / 2;
            todo.push(chunk[mid..].to_vec());
            todo.push(chunk[..mid].to_vec());
            continue;
        }
        for (id, answer) in chunk.into_iter().zip(answers) {
            if let (Err(cap), Some(metrics)) = (answer, metrics) {
                tracing::error!(reason = cap_reason(cap), "object index lookup capped");
                metrics.incr(
                    METRIC_INDEX_LOOKUP_CAPPED,
                    &[("reason", cap_reason(cap))],
                    1,
                );
            }
            found.insert(id, answer);
        }
    }
    Ok(found)
}

/// Read one bounded range into memory, preserving the blob contract's
/// streaming cap and refusing short or overlong backend responses.
async fn frame_bytes<B: BlobStore>(
    blobs: &B,
    pack: Hash,
    offset: u64,
    length: u64,
    budget: u64,
) -> Result<Vec<u8>, ServerError> {
    if length == 0 {
        return Err(ServerError::invalid_argument("object hash mismatch"));
    }
    if length > budget {
        return Err(budget_exceeded());
    }
    let end = offset.checked_add(length - 1).ok_or_else(unavailable)?;
    let body = blobs
        .get(
            &BlobKey::pack(pack),
            Some(ByteRange {
                start: offset,
                end_inclusive: end,
            }),
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    let mut bytes = Vec::new();
    match body {
        BlobBody::Bytes(value) => {
            if value.len() as u64 != length {
                return Err(unavailable());
            }
            bytes.extend_from_slice(&value);
        }
        BlobBody::Stream { mut stream, .. } => {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| unavailable())?;
                if (bytes.len() as u64).saturating_add(chunk.len() as u64) > length {
                    return Err(unavailable());
                }
                bytes.extend_from_slice(&chunk);
            }
        }
    }
    if bytes.len() as u64 != length {
        return Err(unavailable());
    }
    Ok(bytes)
}

struct CachedBase(Option<(Hash, Arc<[u8]>)>);
impl DeltaBaseSource for CachedBase {
    const VERIFIED: bool = false;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self
            .0
            .as_ref()
            .filter(|(base, _)| base == id)
            .map(|(_, bytes)| bytes.to_vec()))
    }
}

type Location = (Hash, Hash, u64);

/// Canonical member bytes and their total delta depth.
pub type ResolvedMember = (Arc<[u8]>, u32);

/// Canonical member bytes retained during one verification. Each location is
/// charged once, even when multiple deltas reuse it as an external base.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberCache {
    rows: BTreeMap<Location, ResolvedMember>,
    retained_bytes: u64,
    remaining_work: Option<u32>,
}

impl MemberCache {
    pub(crate) fn with_work_budget(limit: u32) -> Self {
        Self {
            remaining_work: Some(limit),
            ..Self::default()
        }
    }

    pub(crate) fn charge_work(&mut self, amount: u32) -> Result<(), ResolveFailure> {
        if let Some(remaining) = &mut self.remaining_work {
            *remaining = remaining
                .checked_sub(amount)
                .ok_or(ResolveFailure::Capped)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    fn insert(
        &mut self,
        location: Location,
        value: ResolvedMember,
        budget: u64,
    ) -> Result<(), ResolveFailure> {
        let used = self
            .retained_bytes
            .checked_add(value.0.len() as u64)
            .ok_or_else(budget_exceeded)?;
        if used > budget {
            return Err(budget_exceeded().into());
        }
        self.rows.insert(location, value);
        self.retained_bytes = used;
        Ok(())
    }
}

/// Resolve a member object's canonical bytes and total depth. Memoization
/// shares repeated external bases across the consuming advance.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn member_object<'a, B: BlobStore, S: NamespaceStore>(
    blobs: &'a B,
    store: &'a S,
    shards: &'a dyn ShardMap,
    repo: &'a RepoId,
    id: Hash,
    located: LocatedObject,
    cap: u32,
    budget: u64,
    memo: &'a mut MemberCache,
    visiting: &'a mut BTreeSet<Location>,
    metrics: &'a dyn Metrics,
) -> BoxFuture<'a, Result<ResolvedMember, ResolveFailure>> {
    Box::pin(async move {
        let location = (id, located.pack, located.value.frame_offset);
        let available = budget
            .checked_sub(memo.retained_bytes)
            .ok_or_else(budget_exceeded)?;
        if let Some(value) = memo.rows.get(&location) {
            if value.1 > cap {
                return Err(ServerError::invalid_argument("delta chain too deep").into());
            }
            return Ok(value.clone());
        }
        // An ancestry frontier is already charged by the walk; recursive,
        // uncached delta bases share its work budget. Cache hits are free.
        if !visiting.is_empty() {
            memo.charge_work(1)?;
        }
        if !visiting.insert(location) {
            return Err(ServerError::invalid_argument("delta chain too deep").into());
        }
        let result = async {
            let IndexValue {
                frame_offset,
                frame_length,
                delta_base,
                ..
            } = located.value;
            let prefix = frame_bytes(blobs, located.pack, 0, 8, available).await?;
            let version = u32::from_le_bytes(prefix[4..8].try_into().map_err(|_| unavailable())?);
            let mut depth = 0;
            let mut base_bytes = None;
            if let Some(base) = delta_base {
                // A raw terminal base may be one node beyond the hop cap;
                // another delta may not. Stop before a long chain recurses.
                if visiting.len() > usize::try_from(cap).unwrap_or(usize::MAX) {
                    return Err(ServerError::invalid_argument("delta chain too deep").into());
                }
                let partition = shards.object_index(repo, &base);
                let key = keys::object_index(&repo.name, &base, &located.pack);
                let same = store
                    .get_many(&partition, &[key])
                    .await
                    .map_err(|_| unavailable())?;
                if same.len() != 1 {
                    return Err(unavailable().into());
                }
                let same = same.into_iter().next().flatten();
                let next = if let Some(value) = same {
                    let value =
                        codec::decode_object_index(&base, &value).map_err(|_| unavailable())?;
                    (value.frame_offset < frame_offset).then_some(LocatedObject {
                        pack: located.pack,
                        value,
                    })
                } else {
                    None
                };
                let next = match next {
                    Some(next) => next,
                    None => match locate_split(store, shards, repo, &[base], metrics)
                        .await?
                        .remove(&base)
                    {
                        Some(Ok(Some(next))) => next,
                        Some(Err(_)) => return Err(ResolveFailure::Capped),
                        _ => return Err(ResolveFailure::Missing),
                    },
                };
                let (canonical, base_depth) = member_object(
                    blobs, store, shards, repo, base, next, cap, budget, memo, visiting, metrics,
                )
                .await?;
                base_bytes = Some((base, canonical));
                depth = base_depth.saturating_add(1);
                if depth > cap {
                    return Err(ServerError::invalid_argument("delta chain too deep").into());
                }
            }
            let available = budget
                .checked_sub(memo.retained_bytes)
                .ok_or_else(budget_exceeded)?;
            let frame =
                frame_bytes(blobs, located.pack, frame_offset, frame_length, available).await?;
            let mut source = CachedBase(base_bytes);
            let (actual, bytes) = decode_frame_with(
                &frame,
                version,
                &mut source,
                DecodeLimits::default().with_max_decoded_bytes(available),
            )
            .map_err(|error| {
                ResolveFailure::Other(if matches!(error, PackError::PackfileTooLarge) {
                    budget_exceeded()
                } else {
                    ServerError::invalid_argument("object hash mismatch")
                })
            })?;
            if actual != id {
                return Err(ServerError::invalid_argument("object hash mismatch").into());
            }
            Ok((Arc::from(bytes), depth))
        }
        .await;
        visiting.remove(&location);
        let value = result?;
        memo.insert(location, value.clone(), budget)?;
        Ok(value)
    })
}
