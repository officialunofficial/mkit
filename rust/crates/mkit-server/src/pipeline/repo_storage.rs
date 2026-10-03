//! The repository stored-bytes read and the owner authority it shares with
//! owner object reads (SPEC-SERVER §6.5.1).

use std::sync::atomic::{AtomicBool, Ordering};

use mkit_core::repo_identity::Namespace;

use super::{AuthMode, CallerView, HookSet, OpKind, Pipeline, RequestMeta, read_policy};
use crate::indexed::budget::Budgeted;
use crate::store::{MultipartBlobStore, NamespaceStore};
use crate::{Code, RepoId, ServerError};

/// Stable public message for exhausted owner-read allowances.
pub(super) const OWNER_READ_LIMIT_MESSAGE: &str = "object reader limit exceeded";

pub(super) fn exhausted() -> ServerError {
    ServerError::resource_exhausted(OWNER_READ_LIMIT_MESSAGE)
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Verify a signed owner envelope for `repo`: the authority an owner
    /// read of the repository requires.
    pub(super) async fn authorize_owner(
        &self,
        repo: &RepoId,
        meta: &RequestMeta<'_>,
    ) -> Result<(), ServerError> {
        if !matches!(self.cfg.auth, AuthMode::AuthV2(_)) {
            return Err(ServerError::unauthenticated("auth v2 required"));
        }
        let a = self.authenticate(meta)?;
        if a.auth.is_none() || a.repo().repo != *repo {
            return Err(ServerError::unauthenticated("envelope mismatch"));
        }
        let op = self.identify(
            &a,
            OpKind::ListRefs {
                prefix: "refs/".into(),
            },
        )?;
        let capped = AtomicBool::new(false);
        let store = Budgeted::capture(&self.meta, &capped);
        let auth = self
            .authorize_read_with_meta(&op, &store, None)
            .await
            .map_err(|error| {
                if capped.load(Ordering::SeqCst) {
                    exhausted()
                } else {
                    error
                }
            })?;
        let owner = Namespace::parse(repo.namespace.as_str()).is_ok_and(
            |n| matches!(n, Namespace::Ed25519(key) if a.principal.ed25519() == Some(&key)),
        );
        let grant = self.visibility_gates_reads()
            && auth.facts.grant.is_some()
            && op
                .write_grant
                .as_ref()
                .zip(self.cfg.grants.as_ref())
                .and_then(|(h, c)| read_policy::check_grant(c, h.expose(), &op))
                .is_some_and(|g| g.write);
        if auth.facts.caller_view != CallerView::Writer || !(owner || grant) {
            return Err(ServerError::permission_denied("writer authority required"));
        }
        Ok(())
    }

    /// The repository's stored-bytes counter: the absolute pack-byte total
    /// and its monotonic version, in one coordinator read. Authorized like an
    /// owner object read. The value is exact and eventually consistent: it
    /// trails consumed packs by the relay lag (SPEC-SERVER §6.5.1).
    ///
    /// # Errors
    /// Invalid or non-owner credentials, a deployment without
    /// multi-repository addressing, or a store failure.
    pub async fn repo_storage(
        &self,
        repo: &RepoId,
        meta: &RequestMeta<'_>,
    ) -> Result<RepoStorage, ServerError> {
        if !matches!(self.cfg.addressing, crate::repo::Addressing::Multi(_)) {
            return Err(ServerError::new(
                Code::Unimplemented,
                "repository storage needs multi-repository addressing",
            ));
        }
        self.authorize_owner(repo, meta).await?;
        let raw = self
            .meta
            .get(
                &self.shards.coordinator(&repo.namespace),
                &crate::store::keys::repo_storage(&repo.name),
            )
            .await
            .map_err(super::meta_error)?
            .ok_or_else(|| super::internal("repository counter missing"))?;
        let state = crate::store::codec::decode_repo_storage(&raw).map_err(super::meta_error)?;
        Ok(RepoStorage {
            stored_bytes: state.stored_bytes,
            version: state.version,
        })
    }
}
/// A repository's stored-bytes counter at one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoStorage {
    /// Sum of the sizes of the distinct packs that are members of the repository.
    pub stored_bytes: u64,
    /// Monotonic; a larger version supersedes a smaller one.
    pub version: u64,
}
