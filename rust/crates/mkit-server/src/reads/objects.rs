//! Repository membership queries and bounded canonical decoding.
use super::{ReadAccess, classify, corrupt, failure};
use crate::indexed::resolve::{MemberCache, ResolveFailure, member_object};
use crate::store::{BlobStore, NamespaceStore, index};
use crate::{RepoId, ServerError};
use mkit_core::hash::Hash;
use mkit_core::object::ObjectType;
use std::collections::BTreeSet;

/// Maximum IDs in one typed member-location query.
pub const MAX_OBJECT_LOOKUP_IDS: usize = index::MAX_LOOKUP_IDS;

/// A repository member's pack location, with a fresh denial observation.
/// This is membership evidence, not ref reachability or permission to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberObject {
    pub pack: Hash,
    pub frame_offset: u64,
    pub frame_length: u64,
    pub decoded_size: u64,
    /// Frame delta hops, excluding ancestry inside an external base.
    pub in_pack_delta_depth: u32,
    pub delta_base: Option<Hash>,
    /// The object or its member pack is currently denied.
    /// Disabled takedown denial reports false without reading denial rows.
    /// A false observation does not replace a final serving guard.
    pub denied: bool,
}

/// Validated immutable inventory for a member object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberInventory {
    /// `None` denotes an opaque entry, whose canonical kind is unknown.
    pub kind: Option<ObjectType>,
    pub canonical_len: u64,
    pub logical_len: Option<u64>,
    pub base: Option<Hash>,
}

/// Caller-selected bounds for a canonical member read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberReadLimits {
    pub max_delta_depth: u32,
    /// Aggregate decoded bytes, including external bases.
    pub max_decode_bytes: u64,
}

/// Canonical bytes verified against the requested object ID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanonicalMember {
    pub bytes: std::sync::Arc<[u8]>,
    pub delta_depth: u32,
    /// Decode work retained by this call, including external bases.
    pub decoded_bytes: u64,
}

impl<N: NamespaceStore> ReadAccess<'_, N> {
    async fn locations(
        &self,
        repo: &RepoId,
        ids: &[Hash],
    ) -> Result<Vec<Option<index::LocatedObject>>, ServerError> {
        if ids.len() > MAX_OBJECT_LOOKUP_IDS {
            return Err(ServerError::invalid_argument("too many object IDs"));
        }
        let answers = index::locate_many(&self.store, self.shards, repo, ids)
            .await
            .map_err(classify)?;
        if answers.len() != ids.len() {
            return Err(failure());
        }
        answers
            .into_iter()
            .map(|answer| answer.map_err(|_| failure()))
            .collect()
    }

    async fn locate(
        &self,
        repo: &RepoId,
        id: &Hash,
    ) -> Result<Option<index::LocatedObject>, ServerError> {
        Ok(self.locations(repo, &[*id]).await?.pop().flatten())
    }

    /// Fresh denial for `id`, classified like every other typed read.
    async fn object_denied(&self, id: &Hash) -> Result<bool, ServerError> {
        crate::store::ContentIndex::new(crate::store::BorrowedStore(&self.store))
            .blocked(id)
            .await
            .map(|entry| entry.is_some())
            .map_err(classify)
    }

    async fn describe(
        &self,
        id: &Hash,
        located: index::LocatedObject,
    ) -> Result<MemberObject, ServerError> {
        // Do not short-circuit: a corrupt pack denial row is still a fault.
        let object_denied = self.object_denied(id).await?;
        let pack_denied = self.object_denied(&located.pack).await?;
        Ok(MemberObject {
            pack: located.pack,
            frame_offset: located.value.frame_offset,
            frame_length: located.value.frame_length,
            decoded_size: located.value.decoded_size,
            in_pack_delta_depth: located.value.chain_depth,
            delta_base: located.value.delta_base,
            denied: object_denied || pack_denied,
        })
    }

    /// Batch [`Self::locate_object`] queries through the existing member index.
    /// Answers retain input order and duplicates. Each returned member has a
    /// fresh object and pack denial observation when denial is enabled; this
    /// is not an atomic snapshot. Disabled denial reports clear without I/O.
    /// No repository authorization or ref reachability check runs here.
    ///
    /// # Errors
    /// `invalid_argument` above [`MAX_OBJECT_LOOKUP_IDS`]; `internal` for
    /// corrupt rows; `unavailable` for lookup caps, malformed replies, or
    /// failed reads. Any failed proof refuses the batch.
    pub async fn locate_objects(
        &self,
        repo: &RepoId,
        ids: &[Hash],
    ) -> Result<Vec<Option<MemberObject>>, ServerError> {
        let locations = self.locations(repo, ids).await?;
        let mut answers = Vec::with_capacity(ids.len());
        for (id, located) in ids.iter().zip(locations) {
            answers.push(match located {
                Some(located) => Some(self.describe(id, located).await?),
                None => None,
            });
        }
        Ok(answers)
    }

    /// Locate one object using live repository membership and, when enabled,
    /// live denial rows.
    /// Absence means no member pack, irrespective of global object existence.
    /// Denied members remain visible to trusted policy code with `denied = true`.
    /// No repository authorization or ref reachability check runs here.
    ///
    /// # Errors
    /// `internal` for a corrupt row; `unavailable` for lookup caps, malformed
    /// replies, or storage failures.
    pub async fn locate_object(
        &self,
        repo: &RepoId,
        id: &Hash,
    ) -> Result<Option<MemberObject>, ServerError> {
        let Some(located) = self.locate(repo, id).await? else {
            return Ok(None);
        };
        self.describe(id, located).await.map(Some)
    }

    /// Read validated inventory after a fresh member lookup. Missing membership
    /// or inventory returns `None`; malformed inventory fails closed.
    /// Denial does not hide immutable inventory from trusted policy code.
    ///
    /// # Errors
    /// `internal` for a corrupt or contradictory row; `unavailable` for lookup
    /// caps, malformed replies, or storage failures.
    pub async fn member_inventory(
        &self,
        repo: &RepoId,
        id: &Hash,
    ) -> Result<Option<MemberInventory>, ServerError> {
        let Some(located) = self.locate(repo, id).await? else {
            return Ok(None);
        };
        let Some(row) = crate::takedown::inventory::entry(&self.store, &located.pack, id)
            .await
            .map_err(classify)?
        else {
            return Ok(None);
        };
        let kind = match row.kind {
            0 => None,
            1 => Some(ObjectType::Blob),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Commit),
            4 => Some(ObjectType::Remix),
            5 => Some(ObjectType::ChunkedBlob),
            6 => Some(ObjectType::Delta),
            7 => Some(ObjectType::Tag),
            _ => return Err(corrupt("invalid inventory object kind")),
        };
        Ok(Some(MemberInventory {
            kind,
            canonical_len: row.canonical_len,
            logical_len: row.logical_len,
            base: row.base,
        }))
    }

    /// Decode a freshly located member, including bounded external delta bases.
    /// The resolver verifies canonical IDs and applies live object and pack
    /// denial at its existing boundaries when enabled. Disabled denial never
    /// consults block or action rows. Each call starts an empty decode memo.
    /// Membership alone does not prove public reachability. Use this only after
    /// authorizing the repository; content endpoints keep their final guards.
    ///
    /// # Errors
    /// Resolver errors for denied objects or exhausted decode bounds;
    /// `internal` for a corrupt frame or row; `unavailable` for lookup caps,
    /// malformed replies, or failed storage reads.
    pub async fn read_member_canonical<B: BlobStore>(
        &self,
        blobs: &B,
        repo: &RepoId,
        id: Hash,
        limits: MemberReadLimits,
    ) -> Result<Option<CanonicalMember>, ServerError> {
        let Some(located) = self.locate(repo, &id).await? else {
            return Ok(None);
        };
        let mut memo = MemberCache::default();
        let (bytes, delta_depth) = member_object(
            blobs,
            &self.store,
            self.shards,
            repo,
            id,
            located,
            limits.max_delta_depth,
            limits.max_decode_bytes,
            &mut memo,
            &mut BTreeSet::new(),
            &crate::NoopMetrics,
        )
        .await
        .map_err(|error| match error {
            ResolveFailure::Other(error) => error,
            ResolveFailure::Corrupt(error) => corrupt(error),
            ResolveFailure::Missing | ResolveFailure::Capped => failure(),
        })?;
        Ok(Some(CanonicalMember {
            bytes,
            delta_depth,
            decoded_bytes: memo.retained_bytes(),
        }))
    }
}
