//! Multi-repository creation is observed after replay lookup and committed
//! only after authorization and admission allow the write. Coordinator rows
//! commit before the ref batch: a crash can leave an empty registered repo
//! (which Single `ListRefs` shows as empty), never refs in an unregistered repo.
//! Steady writes use the ref shard's repo-known marker and skip the coordinator.

use crate::error::ServerError;
use crate::op::{Creation, Operation};
use crate::repo::Addressing;
use crate::store::{Batch, BatchOutcome, BlobStore, NamespaceStore, Precondition, codec, keys};

use super::{HookSet, Pipeline, Snapshot, internal, meta_error, ms};

impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn creation_facts(
        &self,
        op: &Operation,
        ahead: Option<&Snapshot>,
    ) -> Result<Creation, ServerError> {
        if !matches!(self.cfg.addressing, Addressing::Multi(_)) {
            return Ok(Creation::default());
        }
        if ahead.is_some_and(|snap| snap.get(&keys::repo_known(&op.repo.name)).is_some()) {
            return Ok(Creation::default());
        }
        self.read_creation(op).await
    }

    async fn read_creation(&self, op: &Operation) -> Result<Creation, ServerError> {
        let p = self.shards.coordinator(&op.repo.namespace);
        let wanted = [keys::namespace_record(), keys::repo_record(&op.repo.name)];
        let rows = self.meta.get_many(&p, &wanted).await.map_err(meta_error)?;
        let [namespace, repo] = rows.as_slice() else {
            return Err(internal(
                "coordinator get_many returned the wrong row count",
            ));
        };
        if let Some(value) = namespace {
            codec::decode_namespace_record(value).map_err(meta_error)?;
        }
        if let Some(value) = repo {
            codec::decode_repo_record(value).map_err(meta_error)?;
        }
        if namespace.is_none() && repo.is_some() {
            return Err(internal("repository registered without a namespace"));
        }
        Ok(Creation {
            namespace: namespace.is_none(),
            repo: repo.is_none(),
        })
    }

    pub(super) async fn commit_creation(
        &self,
        op: &Operation,
        business_skew_ms: i64,
    ) -> Result<Creation, ServerError> {
        let creation = op.creation;
        if !creation.namespace && !creation.repo {
            return Ok(Creation::default());
        }
        let created_at_ms = ms(self.clock.now_ms().saturating_add(business_skew_ms));
        let mut batch = Batch::new();
        if creation.namespace {
            let key = keys::namespace_record();
            let record = codec::NamespaceRecord {
                created_at_ms,
                config_version: 1,
            };
            batch = batch
                .require(Precondition::Absent(key.clone()))
                .put(key, codec::encode_namespace_record(&record));
        }
        if creation.repo {
            let key = keys::repo_record(&op.repo.name);
            let record = codec::RepoRecord { created_at_ms };
            batch = batch
                .require(Precondition::Absent(key.clone()))
                .put(key, codec::encode_repo_record(&record));
        }
        let p = self.shards.coordinator(&op.repo.namespace);
        match self.meta.apply(&p, batch).await.map_err(meta_error)? {
            BatchOutcome::Committed => Ok(creation),
            BatchOutcome::PreconditionFailed { .. } => {
                let after = self.read_creation(op).await?;
                if after.namespace || after.repo {
                    Err(internal("coordinator creation race left missing rows"))
                } else {
                    Ok(Creation::default())
                }
            }
            BatchOutcome::DeadlinePassed { .. } => {
                Err(internal("coordinator batch had no deadline"))
            }
        }
    }
}
