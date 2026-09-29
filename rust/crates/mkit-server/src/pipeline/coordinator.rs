//! Multi-repository creation is observed after replay lookup and committed
//! only after authorization and admission allow the write. Coordinator rows
//! commit before the ref batch: a crash can leave an empty registered repo
//! (which Single `ListRefs` shows as empty), never refs in an unregistered repo.
//! Steady writes use the ref shard's repo-known marker and skip the coordinator.

use crate::error::ServerError;
use crate::op::{Creation, Operation};
use crate::repo::Addressing;
use crate::store::{
    Batch, BatchOutcome, MultipartBlobStore, NamespaceStore, Precondition, codec, keys,
};

use super::{HookSet, Pipeline, Snapshot, internal, meta_error, ms};

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
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
        let p = self.shards.coordinator(&op.repo.namespace);
        // Rows only ever go from absent to present, so a lost race leaves at
        // most the rows another writer has not created yet: re-read and
        // create only those. A second writer racing for a different repo in
        // a new namespace loses on `nr` and still registers its own `rr`.
        let mut want = creation;
        for _ in 0..CREATION_ATTEMPTS {
            let mut batch = Batch::new();
            if let Some(grant) = op.authz.grant {
                let key = keys::grant_epoch();
                let observed = self.meta.get(&p, &key).await.map_err(meta_error)?;
                let epoch = observed
                    .as_ref()
                    .map(codec::decode_u64)
                    .transpose()
                    .map_err(meta_error)?
                    .unwrap_or(0);
                if epoch != grant.epoch {
                    return Err(super::plan::epoch_moved());
                }
                batch = batch.require(super::lease::observed_guard(key, observed.as_ref()));
            }
            if want.namespace {
                let key = keys::namespace_record();
                let record = codec::NamespaceRecord {
                    created_at_ms,
                    config_version: 1,
                };
                batch = batch
                    .require(Precondition::Absent(key.clone()))
                    .put(key, codec::encode_namespace_record(&record));
            }
            if want.repo {
                let key = keys::repo_record(&op.repo.name);
                let record = codec::RepoRecord { created_at_ms };
                batch = batch
                    .require(Precondition::Absent(key.clone()))
                    .put(key, codec::encode_repo_record(&record));
            }
            match self.meta.apply(&p, batch).await.map_err(meta_error)? {
                BatchOutcome::Committed => return Ok(want),
                BatchOutcome::PreconditionFailed { .. } => {
                    want = self.read_creation(op).await?;
                    if !want.namespace && !want.repo {
                        return Ok(Creation::default());
                    }
                }
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("coordinator batch had no deadline"));
                }
            }
        }
        Err(internal("coordinator creation did not settle"))
    }
}

/// Coordinator creation batches one write attempts: the first, one after
/// losing `nr`, and one after losing `rr` to a same-repo writer.
pub(super) const CREATION_ATTEMPTS: usize = 3;
