//! The repository stored-bytes read and the owner authority it shares with
//! owner object reads (SPEC-SERVER §6.5.1).

use std::sync::atomic::{AtomicBool, Ordering};

use mkit_core::repo_identity::Namespace;

use super::{
    AuthMode, Authenticated, CallerView, HookSet, OpKind, Pipeline, RequestMeta, read_policy,
};
use crate::indexed::budget::Budgeted;
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, MultipartBlobStore, NamespaceStore, Partition,
    PartitionStats, ScanPage, StoreCapabilities, StoreError, Value,
};
use crate::{Code, NamespaceKey, RepoId, RepoName, ServerError};

/// Maximum repository names accepted by [`Pipeline::repo_storage_many`].
pub const MAX_REPO_STORAGE_BATCH: usize = 100;

// Serve the ordinary owner authorization reads from the same coordinator
// snapshot as the counters. Never fall through to another backend read.
struct CoordinatorRead {
    partition: Partition,
    rows: std::collections::BTreeMap<Key, Option<Value>>,
    capabilities: StoreCapabilities,
}

impl NamespaceStore for CoordinatorRead {
    fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        if *p != self.partition {
            return Err(StoreError::Invalid("snapshot partition mismatch".into()));
        }
        self.rows
            .get(key)
            .cloned()
            .ok_or_else(|| StoreError::Invalid("key outside coordinator snapshot".into()))
    }

    async fn scan(
        &self,
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        Err(StoreError::Unsupported(
            "coordinator snapshot cannot scan".into(),
        ))
    }

    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Unsupported(
            "coordinator snapshot cannot write".into(),
        ))
    }

    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        Err(StoreError::Unsupported(
            "coordinator snapshot has no statistics".into(),
        ))
    }

    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

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
    ) -> Result<super::Authenticated, ServerError> {
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
        self.authorize_owner_operation(&a, &op, &self.meta).await
    }

    async fn authorize_owner_operation<S: NamespaceStore>(
        &self,
        a: &Authenticated,
        op: &crate::op::Operation,
        meta: &S,
    ) -> Result<(), ServerError> {
        let repo = &op.repo;
        let capped = AtomicBool::new(false);
        let store = Budgeted::capture(meta, &capped);
        let auth = self
            .authorize_read_with_meta(op, &store, None)
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
                .and_then(|(h, c)| read_policy::check_grant(c, h.expose(), op))
                .is_some_and(|g| g.write);
        if auth.facts.caller_view != CallerView::Writer || !(owner || grant) {
            return Err(ServerError::permission_denied("writer authority required"));
        }
        Ok(a)
    }

    /// Read at most [`MAX_REPO_STORAGE_BATCH`] counters in input order,
    /// preserving duplicates. One coordinator `get_many` fetches both counters
    /// and authorization state; an empty batch performs no storage call.
    /// Values have the same relay lag as [`Self::repo_storage`].
    ///
    /// Supply a signed `ListRefs` envelope whose repository selects `namespace`.
    /// Its name need not exist. Each requested repository then undergoes the
    /// same owner/grant and authorizer checks as [`Self::repo_storage`].
    /// Unauthorized and missing repositories both return `None`, including
    /// authorizer failures; denied rows' counters are never decoded.
    /// Authorizer calls remain per repository.
    ///
    /// # Errors
    /// Oversized batches, invalid or namespace-mismatched credentials,
    /// non-Multi addressing, backend failures, or corrupt authorized rows.
    /// Backend implementations using the default `get_many` may perform
    /// multiple local reads; this method makes one coordinator store call.
    pub async fn repo_storage_many(
        &self,
        namespace: &NamespaceKey,
        repos: &[RepoName],
        meta: &RequestMeta<'_>,
    ) -> Result<Vec<Option<RepoStorage>>, ServerError> {
        if !matches!(self.cfg.addressing, crate::repo::Addressing::Multi(_)) {
            return Err(ServerError::new(
                Code::Unimplemented,
                "repository storage needs multi-repository addressing",
            ));
        }
        if repos.len() > MAX_REPO_STORAGE_BATCH {
            return Err(ServerError::invalid_argument(
                "repository storage batch exceeds 100",
            ));
        }
        if !matches!(self.cfg.auth, AuthMode::AuthV2(_)) {
            return Err(ServerError::unauthenticated("auth v2 required"));
        }
        let a = self.authenticate(meta)?;
        if a.auth.is_none() || a.repo().repo.namespace != *namespace {
            return Err(ServerError::unauthenticated("envelope mismatch"));
        }
        let mut op = self.identify(
            &a,
            OpKind::ListRefs {
                prefix: "refs/".into(),
            },
        )?;
        if repos.is_empty() {
            return Ok(Vec::new());
        }
        let mut keys = vec![crate::store::keys::grant_epoch()];
        for repo in repos {
            keys.extend([
                crate::store::keys::repo_record(repo),
                crate::store::keys::repo_visibility(repo),
                crate::store::keys::repo_storage(repo),
            ]);
        }
        let partition = self.shards.coordinator(namespace);
        let rows = self
            .meta
            .get_many(&partition, &keys)
            .await
            .map_err(super::meta_error)?;
        if rows.len() != keys.len() {
            return Err(super::internal("short repository storage batch"));
        }
        let snapshot = CoordinatorRead {
            partition,
            rows: keys.into_iter().zip(rows).collect(),
            capabilities: self.meta.capabilities(),
        };
        let mut result = Vec::with_capacity(repos.len());
        for repo in repos {
            op.repo = RepoId {
                namespace: namespace.clone(),
                name: repo.clone(),
            };
            if self
                .authorize_owner_operation(&a, &op, &snapshot)
                .await
                .is_err()
            {
                result.push(None);
                continue;
            }
            let raw = snapshot
                .rows
                .get(&crate::store::keys::repo_storage(repo))
                .and_then(Option::as_ref)
                .ok_or_else(|| super::internal("repository counter missing"))?;
            let state = crate::store::codec::decode_repo_storage(raw).map_err(super::meta_error)?;
            result.push(Some(RepoStorage {
                stored_bytes: state.stored_bytes,
                version: state.version,
            }));
        }
        Ok(result)
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
