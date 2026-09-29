//! Published resolution and byte sourcing (SPEC-HTTP-OBJECTS §4, §5.1;
//! SPEC-SERVER §9.6, R-163). Generic over the stores, so it never touches
//! the pipeline's private state.
//!
//! Membership and reachability are decided from **this repository's** index
//! rows and published refs only. The global object store is read after that,
//! and only for an id this repository holds (its holder row): it never
//! decides existence, membership or reachability, and another repository's
//! extraction is never served.

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use mkit_core::hash::Hash;
use mkit_core::object::{Object, ObjectType};
use mkit_core::serialize::deserialize;

use super::body::{self, EndHook, HttpBody};
use super::{HttpObjectsConfig, METRIC_HTTP_INLINE_CAPPED};
use crate::indexed::IndexedConfig;
use crate::indexed::resolve::{self, DECODE_BUDGET_MESSAGE, MemberCache, ResolveFailure};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::index::{LocatedObject, LookupError, ObjectLookup};
use crate::store::{BlobBody, BlobKey, BorrowedStore, ByteRange, ContentIndex, Holder};
use crate::telemetry::Metrics;
use crate::{BlobStore, NamespaceStore, ServerError};

/// Canonical Blob bytes are a 6-byte prologue, a `u32` length, then the data.
const BLOB_HEADER: u64 = 10;
/// [`BLOB_HEADER`] as an index.
const BLOB_HEADER_INDEX: usize = 10;
/// Match git-import: at most 16 tags, plus the terminal commit or remix.
const MAX_PEEL: usize = 16;

/// The stores and limits one request resolves against.
pub(crate) struct Env<'a, B, N> {
    pub blobs: &'a B,
    pub meta: &'a N,
    pub shards: &'a dyn ShardMap,
    pub repo: &'a RepoId,
    pub indexed: &'a IndexedConfig,
    pub cfg: &'a HttpObjectsConfig,
    pub metrics: &'a dyn Metrics,
}

/// The decode bytes one request may still spend, shared by resolution, the
/// reachability walk and the inline byte source.
pub(crate) struct Budget(pub u64);

/// Why resolution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Miss {
    /// Not a member, not reachable, wrong type: the uniform 404.
    NotFound,
    /// A cap held the request back: the decode budget or the walk size.
    Capped,
    /// A store failed or held inconsistent state: 503.
    Unavailable,
}

impl From<ServerError> for Miss {
    fn from(_: ServerError) -> Self {
        Self::Unavailable
    }
}

/// The object type of canonical bytes, from the prologue tag alone.
pub(crate) fn type_of(canonical: &[u8]) -> Option<ObjectType> {
    Some(match canonical.first()? {
        0x01 => ObjectType::Blob,
        0x02 => ObjectType::Tree,
        0x03 => ObjectType::Commit,
        0x04 => ObjectType::Remix,
        0x05 => ObjectType::ChunkedBlob,
        0x06 => ObjectType::Delta,
        0x07 => ObjectType::Tag,
        _ => return None,
    })
}

/// One index answer as a membership decision: a missing row and an
/// unprovable one (`TooManyRows`, R-148: not retryable) are both "not a
/// member"; a residual retryable cap is a failure of the request, never a
/// silent miss.
fn membership(answer: Option<&ObjectLookup>) -> Result<Option<LocatedObject>, Miss> {
    match answer {
        Some(Ok(Some(located))) => Ok(Some(*located)),
        None | Some(Ok(None) | Err(LookupError::TooManyRows)) => Ok(None),
        Some(Err(_)) => Err(Miss::Unavailable),
    }
}

/// This repository's membership row for `id`.
pub(crate) async fn locate<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    id: Hash,
) -> Result<LocatedObject, Miss> {
    let found = resolve::locate_split(env.meta, env.shards, env.repo, &[id], env.metrics).await?;
    membership(found.get(&id))?.ok_or(Miss::NotFound)
}

/// Locate several ids at once: the members among them, in id order.
pub(crate) async fn locate_many<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    ids: &[Hash],
) -> Result<Vec<(Hash, LocatedObject)>, Miss> {
    let found = resolve::locate_split(env.meta, env.shards, env.repo, ids, env.metrics).await?;
    let mut members = Vec::new();
    for (id, answer) in &found {
        if let Some(located) = membership(Some(answer))? {
            members.push((*id, located));
        }
    }
    Ok(members)
}

/// The canonical bytes of a located member, charged to `budget`.
pub(crate) async fn load<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    id: Hash,
    located: LocatedObject,
    budget: &mut Budget,
) -> Result<Arc<[u8]>, Miss> {
    if located.value.decoded_size > budget.0 {
        return Err(Miss::Capped);
    }
    let mut memo = MemberCache::default();
    let mut visiting = BTreeSet::new();
    let result = resolve::member_object(
        env.blobs,
        env.meta,
        env.shards,
        env.repo,
        id,
        located,
        env.indexed.max_delta_chain_depth,
        budget.0,
        &mut memo,
        &mut visiting,
        env.metrics,
    )
    .await;
    budget.0 = budget.0.saturating_sub(memo.retained_bytes());
    match result {
        Ok((bytes, _)) => Ok(bytes),
        Err(ResolveFailure::Other(error)) if error.public_message() == DECODE_BUDGET_MESSAGE => {
            Err(Miss::Capped)
        }
        Err(_) => {
            tracing::warn!("member object could not be reconstructed");
            Err(Miss::Unavailable)
        }
    }
}

async fn load_object<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    id: Hash,
    budget: &mut Budget,
) -> Result<Arc<[u8]>, Miss> {
    let located = locate(env, id).await?;
    load(env, id, located, budget).await
}

fn decode(bytes: &[u8]) -> Result<Object, Miss> {
    deserialize(bytes).map_err(|_| {
        tracing::warn!("member object failed to decode");
        Miss::Unavailable
    })
}

/// What a ref path resolved to.
pub(crate) struct RefResolved {
    /// The commit or remix the ref peeled to.
    pub commit: Hash,
    /// The object at the end of the path.
    pub leaf: Hash,
}

/// Peel `tip` to a commit or remix and walk its tree by exact decoded entry
/// bytes (§4). A non-tree intermediate or a missing entry is a miss;
/// symlinks are ordinary entries and are never followed.
pub(crate) async fn resolve_ref<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    tip: Hash,
    path: &[Vec<u8>],
    budget: &mut Budget,
) -> Result<RefResolved, Miss> {
    let mut id = tip;
    let mut peeled = None;
    for depth in 0..=MAX_PEEL {
        let bytes = load_object(env, id, budget).await?;
        match type_of(&bytes) {
            Some(ObjectType::Commit | ObjectType::Remix) => {
                let tree = match decode(&bytes)? {
                    Object::Commit(c) => c.tree_hash,
                    Object::Remix(r) => r.tree_hash,
                    _ => return Err(Miss::Unavailable),
                };
                peeled = Some((id, tree));
                break;
            }
            Some(ObjectType::Tag) if depth < MAX_PEEL => match decode(&bytes)? {
                Object::Tag(tag) => id = tag.target,
                _ => return Err(Miss::Unavailable),
            },
            _ => return Err(Miss::NotFound),
        }
    }
    let (commit, mut current) = peeled.ok_or(Miss::NotFound)?;
    for (index, name) in path.iter().enumerate() {
        let bytes = load_object(env, current, budget).await?;
        let Object::Tree(tree) = decode(&bytes)? else {
            return Err(Miss::NotFound);
        };
        let entry = tree
            .entries
            .iter()
            .find(|e| e.name == *name)
            .ok_or(Miss::NotFound)?;
        if index + 1 < path.len() && entry.mode != mkit_core::object::EntryMode::Tree {
            return Err(Miss::NotFound);
        }
        current = entry.object_hash;
    }
    Ok(RefResolved {
        commit,
        leaf: current,
    })
}

/// Where a leaf's representation bytes come from.
pub(crate) enum Source {
    /// Extracted for this repository: read `Object(id)` by range.
    Extracted,
    /// The whole representation, reconstructed from this repository's pack
    /// entry (small objects, non-blob objects, chunk-only blobs).
    Inline(Bytes),
}

/// A resolved leaf: its type, the representation length and its bytes.
pub(crate) struct Leaf {
    pub id: Hash,
    pub ty: ObjectType,
    pub len: u64,
    pub source: Source,
}

fn inconsistent<T>(what: &'static str) -> Result<T, Miss> {
    tracing::error!(what, "extracted object state is inconsistent");
    Err(Miss::Unavailable)
}

async fn head_len<B: BlobStore>(blobs: &B, key: &BlobKey) -> Result<Option<u64>, Miss> {
    match blobs.head(key).await {
        Ok(meta) => Ok(meta.map(|m| m.len)),
        Err(error) => {
            tracing::warn!(detail = %error, "object head failed");
            Err(Miss::Unavailable)
        }
    }
}

/// The content length a chunk-offset sidecar records (its last offset).
async fn sidecar_total<B: BlobStore>(blobs: &B, id: Hash, sidecar_len: u64) -> Result<u64, Miss> {
    // "MKOF", u32 count, then count + 1 u64 offsets.
    if sidecar_len < 16 || !(sidecar_len - 8).is_multiple_of(8) {
        return inconsistent("sidecar length");
    }
    let range = ByteRange {
        start: sidecar_len - 8,
        end_inclusive: sidecar_len - 1,
    };
    let body = blobs
        .get(&BlobKey::object_offsets(id), Some(range))
        .await
        .map_err(|_| Miss::Unavailable)?
        .ok_or(Miss::Unavailable)?;
    let BlobBody::Bytes(tail) = body else {
        return inconsistent("sidecar tail");
    };
    let tail: [u8; 8] = tail
        .as_ref()
        .try_into()
        .or_else(|_| inconsistent("sidecar tail"))?;
    Ok(u64::from_le_bytes(tail))
}

/// Decide the byte source of a member leaf (B9): the extracted copy when
/// this repository holds one, otherwise its own pack entry.
pub(crate) async fn open_leaf<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    id: Hash,
    located: LocatedObject,
    budget: &mut Budget,
) -> Result<Leaf, Miss> {
    let content = ContentIndex::new(BorrowedStore(env.meta));
    let holder = Holder::new(env.repo.namespace.clone(), env.repo.name.clone());
    let held = content
        .holder_record(&id, &holder)
        .await
        .map_err(|error| {
            tracing::warn!(detail = %error, "holder read failed");
            Miss::Unavailable
        })?
        .is_some();
    if held {
        let Some(object_len) = head_len(env.blobs, &BlobKey::object(id)).await? else {
            return inconsistent("holder without an extracted object");
        };
        let sidecar = head_len(env.blobs, &BlobKey::object_offsets(id)).await?;
        let (ty, len) = if let Some(sidecar_len) = sidecar {
            (
                ObjectType::ChunkedBlob,
                sidecar_total(env.blobs, id, sidecar_len).await?,
            )
        } else {
            (
                ObjectType::Blob,
                located.value.decoded_size.saturating_sub(BLOB_HEADER),
            )
        };
        if object_len != len || (ty == ObjectType::Blob && located.value.decoded_size < BLOB_HEADER)
        {
            return inconsistent("extracted length");
        }
        return Ok(Leaf {
            id,
            ty,
            len,
            source: Source::Extracted,
        });
    }
    if located.value.decoded_size > env.cfg.max_inline_object_bytes {
        tracing::warn!("object too large to serve from its pack entry");
        env.metrics.incr(METRIC_HTTP_INLINE_CAPPED, &[], 1);
        return Err(Miss::Unavailable);
    }
    let canonical = load(env, id, located, budget).await?;
    let (ty, bytes) = represent(canonical)?;
    Ok(Leaf {
        id,
        ty,
        len: bytes.len() as u64,
        source: Source::Inline(bytes),
    })
}

/// The representation of a member reconstructed from its pack entry (§5.1):
/// a Blob's data, or the canonical bytes of any other object. A pack-only
/// Delta is never served, and a manifest here means its holder row is
/// missing: the extracted copy is the only source of its content.
fn represent(canonical: Arc<[u8]>) -> Result<(ObjectType, Bytes), Miss> {
    match type_of(&canonical) {
        Some(ObjectType::Delta) => Err(Miss::NotFound),
        Some(ObjectType::ChunkedBlob) => inconsistent("manifest without a holder"),
        Some(ObjectType::Blob) if canonical.len() < BLOB_HEADER_INDEX => inconsistent("short blob"),
        Some(ObjectType::Blob) => Ok((
            ObjectType::Blob,
            Bytes::from_owner(canonical).slice(BLOB_HEADER_INDEX..),
        )),
        Some(ty) => Ok((ty, Bytes::from_owner(canonical))),
        None => inconsistent("unknown object type"),
    }
}

/// The selected bytes of `leaf` as a body. `range` is inclusive and already
/// clamped to the representation; `None` selects all of it. The extracted
/// read enforces the exact length; nothing here reads more than one backend
/// piece at a time. `hook` is taken only once the body is open, so a failure
/// to open leaves it with the caller to report.
pub(crate) async fn open_body<B: BlobStore>(
    blobs: &B,
    leaf: &Leaf,
    range: Option<(u64, u64)>,
    hook: &mut Option<EndHook>,
) -> Result<HttpBody, Miss> {
    let len = range.map_or(leaf.len, |(a, b)| b - a + 1);
    let body = match &leaf.source {
        Source::Inline(bytes) => HttpBody::Bytes(match range {
            Some((a, b)) => match (usize::try_from(a), usize::try_from(b)) {
                (Ok(a), Ok(b)) => bytes.slice(a..=b),
                _ => return Err(Miss::Unavailable),
            },
            None => bytes.clone(),
        }),
        Source::Extracted if len == 0 => HttpBody::Empty,
        Source::Extracted => {
            let read = range.map(|(start, end_inclusive)| ByteRange {
                start,
                end_inclusive,
            });
            let stored = blobs
                .get(&BlobKey::object(leaf.id), read)
                .await
                .map_err(|error| {
                    tracing::warn!(detail = %error, "object read failed");
                    Miss::Unavailable
                })?
                .ok_or(Miss::Unavailable)?;
            let stream = match stored {
                BlobBody::Bytes(bytes) => {
                    Box::pin(futures::stream::once(core::future::ready(Ok(bytes)))) as _
                }
                BlobBody::Stream { len: got, stream } if got == len => stream,
                BlobBody::Stream { .. } => return inconsistent("object stream length"),
            };
            return Ok(body::exact(stream, len, hook.take()));
        }
    };
    Ok(body::with_hook(body, hook.take()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retryable_cap_is_never_a_silent_miss() {
        let located = LocatedObject {
            pack: [1; 32],
            value: crate::store::index::IndexValue {
                frame_offset: 0,
                frame_length: 1,
                wire_type: 0,
                decoded_size: 1,
                chain_depth: 0,
                delta_base: None,
            },
        };
        assert_eq!(membership(Some(&Ok(Some(located)))), Ok(Some(located)));
        for miss in [None, Some(&Ok(None)), Some(&Err(LookupError::TooManyRows))] {
            assert_eq!(membership(miss), Ok(None));
        }
        for cap in [
            LookupError::TooManyPages,
            LookupError::TooManyMembershipReads,
        ] {
            assert_eq!(membership(Some(&Err(cap))), Err(Miss::Unavailable));
        }
    }

    fn bytes(prefix: &[u8]) -> Arc<[u8]> {
        let mut all = prefix.to_vec();
        all.resize(all.len().max(16), 0);
        Arc::from(all)
    }

    #[test]
    fn a_pack_entry_is_represented_by_its_type() {
        let (ty, body) = represent(bytes(&[
            1, b'M', b'K', b'I', b'T', 1, 4, 0, 0, 0, 9, 9, 9, 9,
        ]))
        .unwrap();
        assert_eq!(ty, ObjectType::Blob);
        assert_eq!(&body[..4], &[9, 9, 9, 9]);
        let canonical = bytes(&[2, 1, 2, 3]);
        let (ty, body) = represent(canonical.clone()).unwrap();
        assert_eq!((ty, body.as_ref()), (ObjectType::Tree, &canonical[..]));
        // A short Blob, an unknown tag and a manifest without a holder are
        // inconsistent state.
        for bad in [&[1_u8, 0, 0][..], &[0xee], &[5, 0, 0]] {
            assert_eq!(represent(Arc::from(bad)).err(), Some(Miss::Unavailable));
        }
        // A Delta is never served.
        assert_eq!(represent(bytes(&[6])).err(), Some(Miss::NotFound));
        assert_eq!(type_of(&[]), None);
    }
}
