//! Typed, uncached reads for trusted embedding code.
//!
//! These accessors replace direct storage-layout reads. They do not authorize
//! callers or prove ref reachability. Authorize the repository before calling
//! them, and apply your policy again before disclosing an answer. Use
//! `Pipeline::object_reader` for authorized content serving
//! when the `http-objects` feature is enabled.
//!
//! Every call uses the supplied store and shard map afresh. A caller can supply
//! a budgeted store; lookup and decode bounds are never increased here.

mod fork;
pub use fork::*;
mod objects;
pub use objects::*;
#[cfg(test)]
mod tests;

use crate::pipeline::{RepoVisibility, ShardMap};
use crate::store::{NamespaceStore, codec, keys, publication};
use crate::{RepoId, ServerError};
use mkit_core::hash::Hash;

/// Read access for code that already holds repository authority.
///
/// This facade never writes, caches, authenticates, or calls policy hooks.
/// Private repositories are readable by trusted callers. Do not expose this
/// facade directly as an anonymous endpoint. Existing pipeline read paths
/// retain their uniform absence, authorization, and final guards.
pub struct ReadAccess<'a, N> {
    pub(super) store: &'a N,
    pub(super) shards: &'a dyn ShardMap,
    default_visibility: RepoVisibility,
}

impl<N> core::fmt::Debug for ReadAccess<'_, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReadAccess")
            .field("default_visibility", &self.default_visibility)
            .finish_non_exhaustive()
    }
}

/// An opaque equality token scoped to one repository's visibility observation.
///
/// Compare tokens only across calls using the same configuration. This detects
/// changes to stored observations, not pending changes in an embedder's journal.
/// It is not a monotonic sequence or an authorization credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilityRevision(Hash);

/// One repository's stored visibility and consistency token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepositoryVisibility {
    pub visibility: RepoVisibility,
    pub revision: VisibilityRevision,
}

/// One authoritative published branch observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublishedBranch {
    pub head: Hash,
    pub packmap: Hash,
    /// Last applied advance, including advances awaiting publication.
    pub sequence: u64,
    /// Advance that supplied this published pair.
    pub published_sequence: u64,
    /// Membership incarnation of the published pair.
    pub generation: u64,
}

pub(super) fn failure() -> ServerError {
    ServerError::unavailable("repository read unavailable")
}

impl<'a, N: NamespaceStore> ReadAccess<'a, N> {
    /// Borrow a store and its routing configuration. The default must match
    /// the pipeline's default repository visibility.
    #[must_use]
    pub fn new(store: &'a N, shards: &'a dyn ShardMap, default_visibility: RepoVisibility) -> Self {
        Self {
            store,
            shards,
            default_visibility,
        }
    }

    /// Read and validate the repository and visibility rows together.
    /// A missing visibility row uses the configured default; a missing
    /// repository returns `None`. Corrupt rows never imply public visibility.
    ///
    /// Bracket metadata reads with two calls and require equal revisions.
    /// If your own policy has a journal, also require stable, non-pending
    /// journal observations around both calls. This does not observe that journal.
    /// A successful read does not lock out a later visibility change.
    ///
    /// # Errors
    /// `unavailable` for corrupt rows, malformed replies, or storage failures.
    pub async fn repository_visibility(
        &self,
        repo: &RepoId,
    ) -> Result<Option<RepositoryVisibility>, ServerError> {
        let rows = self
            .store
            .get_many(
                &self.shards.coordinator(&repo.namespace),
                &[
                    keys::repo_record(&repo.name),
                    keys::repo_visibility(&repo.name),
                ],
            )
            .await
            .map_err(|_| failure())?;
        let [record, visibility]: [Option<crate::Value>; 2] =
            rows.try_into().map_err(|_| failure())?;
        let exists = record
            .as_ref()
            .map(codec::decode_repo_record)
            .transpose()
            .map_err(|_| failure())?
            .is_some();
        let stored = visibility
            .as_ref()
            .map(codec::decode_repo_visibility)
            .transpose()
            .map_err(|_| failure())?;
        if !exists {
            return Ok(None);
        }
        let private = crate::pipeline::repo_is_private(stored.as_ref(), self.default_visibility);
        let mut digest = blake3::Hasher::new();
        for bytes in [
            Some(repo.namespace.as_str().as_bytes()),
            Some(repo.name.as_str().as_bytes()),
            record.as_ref().map(crate::Value::as_bytes),
            visibility.as_ref().map(crate::Value::as_bytes),
        ] {
            digest.update(&[u8::from(bytes.is_some())]);
            if let Some(bytes) = bytes {
                digest.update(&(bytes.len() as u64).to_be_bytes());
                digest.update(bytes);
            }
        }
        Ok(Some(RepositoryVisibility {
            visibility: if private {
                RepoVisibility::Private
            } else {
                RepoVisibility::Public
            },
            revision: VisibilityRevision(*digest.finalize().as_bytes()),
        }))
    }

    /// Read the authoritative published head and packmap from one branch row.
    /// Live heads and lagging projections never supply this answer. An absent
    /// or deleted pair returns `None`, including a missing publication ledger.
    /// Authorization, ref denial, and final freshness checks belong to the caller.
    ///
    /// # Errors
    /// `invalid_argument` for a non-branch name; `unavailable` for corrupt rows
    /// or storage failures.
    pub async fn published_branch(
        &self,
        repo: &RepoId,
        branch: &str,
    ) -> Result<Option<PublishedBranch>, ServerError> {
        if !crate::refs::is_served_ref_name(branch) || !branch.starts_with("refs/heads/") {
            return Err(ServerError::invalid_argument("invalid branch name"));
        }
        let state = publication::read(
            self.store,
            &self.shards.ref_shard(repo, branch),
            &repo.name,
            branch,
        )
        .await
        .map_err(|_| failure())?;
        match (state.value.head, state.value.packmap) {
            (Some(head), Some(packmap)) => Ok(Some(PublishedBranch {
                head,
                packmap,
                sequence: state.sequence,
                published_sequence: state.published,
                generation: state.generation,
            })),
            (None, None) => Ok(None),
            _ => Err(failure()),
        }
    }
}
