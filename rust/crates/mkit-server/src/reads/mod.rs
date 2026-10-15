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
//!
//! Error classes: a corrupt or undecodable stored row, or stored rows that
//! contradict each other, is permanent — `internal`. A store or I/O failure
//! and a malformed reply, such as a wrong row count, is retryable —
//! `unavailable`. The embedder decides what reaches its own clients.

mod fork;
pub use fork::*;
mod packs;
pub use packs::*;
mod objects;
pub use objects::*;
#[cfg(test)]
mod tests;

use crate::pipeline::{RepoVisibility, ShardMap};
use crate::store::{DenialReads, NamespaceStore, StoreError, codec, keys, publication};
use crate::{RepoId, ServerError};
use mkit_core::hash::Hash;

/// Read access for code that already holds repository authority.
///
/// This facade never writes, caches, authenticates, or calls policy hooks.
/// Private repositories are readable by trusted callers. Do not expose this
/// facade directly as an anonymous endpoint. Existing pipeline read paths
/// retain their uniform absence, authorization, and final guards.
pub struct ReadAccess<'a, N> {
    pub(super) store: DenialReads<&'a N>,
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

/// One repository's stored visibility declaration and consistency token.
///
/// Unlike [`RepositoryVisibility`], this reports the declared row even when
/// no repository record exists, and never substitutes the configured default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredVisibility {
    /// The declared visibility.
    pub visibility: RepoVisibility,
    /// Opaque equality token over the stored declaration; see
    /// [`VisibilityRevision`].
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

/// A corrupt or undecodable stored row, or stored rows that contradict each
/// other: permanent until the stored data is fixed, never retryable.
pub(super) fn corrupt(detail: impl core::fmt::Display) -> ServerError {
    ServerError::internal("corrupt repository read", detail)
}

/// The public class of a storage failure: a corrupt stored row is permanent;
/// a backend fault or malformed reply may succeed on retry.
pub(super) fn classify(error: StoreError) -> ServerError {
    match error {
        StoreError::Corrupt(_) => corrupt(error),
        StoreError::Unavailable(_)
        | StoreError::Full
        | StoreError::MalformedReply(_)
        | StoreError::SessionGone => failure(),
        other => ServerError::internal("repository read failed", other),
    }
}

impl<'a, N: NamespaceStore> ReadAccess<'a, N> {
    /// Borrow a store and its routing configuration. The default must match
    /// the pipeline's default repository visibility; `takedown_denial` must
    /// match the deployment's denial mode. Disabled denial reports clear
    /// without consulting block or denial-action rows.
    #[must_use]
    pub fn new(
        store: &'a N,
        shards: &'a dyn ShardMap,
        default_visibility: RepoVisibility,
        takedown_denial: bool,
    ) -> Self {
        Self {
            store: DenialReads::new(store, takedown_denial),
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
    /// `internal` for a corrupt row; `unavailable` for a malformed reply or
    /// storage failure.
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
            .map_err(classify)?;
        let [record, visibility]: [Option<crate::Value>; 2] =
            rows.try_into().map_err(|_| failure())?;
        let exists = record
            .as_ref()
            .map(codec::decode_repo_record)
            .transpose()
            .map_err(corrupt)?
            .is_some();
        let stored = visibility
            .as_ref()
            .map(codec::decode_repo_visibility)
            .transpose()
            .map_err(corrupt)?;
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

    /// Read the stored visibility declaration, whether or not the repository
    /// record exists. Private-origin locks and similar flows declare
    /// visibility ahead of the record; this observes that declaration
    /// directly. Returns `None` when no visibility row exists: the caller
    /// decides whether the configured default applies. A corrupt row never
    /// implies public visibility.
    ///
    /// Bracket reads the same way as [`Self::repository_visibility`];
    /// revisions compare only within the same accessor and configuration.
    ///
    /// # Errors
    /// `internal` for a corrupt row; `unavailable` for a malformed reply or
    /// storage failure.
    pub async fn declared_visibility(
        &self,
        repo: &RepoId,
    ) -> Result<Option<DeclaredVisibility>, ServerError> {
        let row = self
            .store
            .get(
                &self.shards.coordinator(&repo.namespace),
                &keys::repo_visibility(&repo.name),
            )
            .await
            .map_err(classify)?;
        let Some(row) = row else { return Ok(None) };
        let stored = codec::decode_repo_visibility(&row).map_err(corrupt)?;
        let mut digest = blake3::Hasher::new();
        for bytes in [
            repo.namespace.as_str().as_bytes(),
            repo.name.as_str().as_bytes(),
            row.as_bytes(),
        ] {
            digest.update(&(bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        Ok(Some(DeclaredVisibility {
            visibility: match stored.visibility {
                codec::StoredVisibility::Private => RepoVisibility::Private,
                codec::StoredVisibility::Public => RepoVisibility::Public,
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
    /// `invalid_argument` for a non-branch name; `internal` for a corrupt row;
    /// `unavailable` for a malformed reply or storage failure.
    pub async fn published_branch(
        &self,
        repo: &RepoId,
        branch: &str,
    ) -> Result<Option<PublishedBranch>, ServerError> {
        if !crate::refs::is_served_ref_name(branch) || !branch.starts_with("refs/heads/") {
            return Err(ServerError::invalid_argument("invalid branch name"));
        }
        let state = publication::read(
            &self.store,
            &self.shards.ref_shard(repo, branch),
            &repo.name,
            branch,
        )
        .await
        .map_err(classify)?;
        match (state.value.head, state.value.packmap) {
            (Some(head), Some(packmap)) => Ok(Some(PublishedBranch {
                head,
                packmap,
                sequence: state.sequence,
                published_sequence: state.published,
                generation: state.generation,
            })),
            _ => Ok(None),
        }
    }
}
