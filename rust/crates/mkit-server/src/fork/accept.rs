//! The ordered source proof and atomic acceptance, before membership installation.

use serde::{Deserialize, Serialize};

use super::{ForkEnv, ForkError, ForkJobV1, ForkResult, plan, publish};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::store::{Batch, NamespaceStore, Precondition, Value, keys};

/// Exact authority observations retained by the operation, including absence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceRowsV1 {
    /// Namespace authority row at admission.
    pub authority: Option<Vec<u8>>,
    /// Grant epoch row at admission.
    pub epoch: Option<Vec<u8>>,
}

impl FenceRowsV1 {
    pub(super) fn check(&self, job: &ForkJobV1, rows: &[Option<Value>]) -> Result<(), ForkError> {
        if rows.first().and_then(Option::as_ref).map(Value::as_bytes) != self.authority.as_deref() {
            return Err(ForkError::Moved("authority"));
        }
        if job.fence.as_ref().is_some_and(|f| f.grant_epoch.is_some())
            && rows.get(1).and_then(Option::as_ref).map(Value::as_bytes) != self.epoch.as_deref()
        {
            return Err(ForkError::Moved("epoch"));
        }
        Ok(())
    }

    pub(super) fn guards(&self, job: &ForkJobV1) -> Vec<Precondition> {
        let guard = |key, row: &Option<Vec<u8>>| match row {
            Some(bytes) => Precondition::Equals(key, Value::new(bytes.clone())),
            None => Precondition::Absent(key),
        };
        let mut guards = vec![guard(keys::authority_generation(), &self.authority)];
        if job.fence.as_ref().is_some_and(|f| f.grant_epoch.is_some()) {
            guards.push(guard(keys::grant_epoch(), &self.epoch));
        }
        guards
    }
}

/// Source policy observations supplied by source and destination authorization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAccessV1 {
    /// Exact stored visibility declaration, including absence.
    pub visibility: Option<Vec<u8>>,
    /// Exact stored visibility revision, including absence.
    pub revision: Option<Vec<u8>>,
}

impl SourceAccessV1 {
    pub(crate) async fn read<S: NamespaceStore>(
        store: &S,
        shards: &dyn crate::pipeline::ShardMap,
        source: &crate::RepoId,
    ) -> Result<Self, ForkError> {
        let rows = store
            .get_many(
                &shards.coordinator(&source.namespace),
                &[
                    keys::repo_visibility(&source.name),
                    keys::repo_visibility_revision(&source.name),
                ],
            )
            .await?;
        let [visibility, revision]: [_; 2] = rows
            .try_into()
            .map_err(|_| ForkError::Unavailable("fork source policy read"))?;
        if let Some(row) = &visibility {
            crate::store::codec::decode_repo_visibility(row)?;
        }
        if let Some(row) = &revision {
            crate::store::codec::decode_u64(row)?;
        }
        Ok(Self {
            visibility: visibility.map(|v| v.as_bytes().to_vec()),
            revision: revision.map(|v| v.as_bytes().to_vec()),
        })
    }
}

/// Prove the complete inherited set only after preparation has finished.
/// A durable cursor bounds each proof unit; no destination membership effects
/// occur in this phase. The final pair and policy observations follow the pack
/// proofs, and the caller commits acceptance with the exact inherited set.
pub(super) async fn slice<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    let store = Budgeted::new(env.store, budget);
    let source = job.source()?;
    let fresh = super::fresh(budget);
    let mut progressed = false;
    while (job.cursor as usize) < job.packs.len() {
        if budget.remaining() < 60 {
            return Ok(false);
        }
        let width = if env.takedown_denial {
            1
        } else {
            super::wave_width(env.store, budget, super::WAVE_UNIT_CALLS)
        };
        let start = job.cursor as usize;
        let end = (start + width).min(job.packs.len());
        let replies = futures::future::join_all(
            job.packs[start..end]
                .iter()
                .map(|pack| publish::prove(env, &store, &source, &pack.id, job.source_generation)),
        )
        .await;
        for reply in replies {
            match reply {
                Ok(()) => {
                    job.cursor += 1;
                    progressed = true;
                }
                Err(error) if super::spent(&error, budget) => {
                    return if progressed || !fresh {
                        Ok(false)
                    } else {
                        Err(ForkError::TooLarge)
                    };
                }
                Err(error) => return Err(error),
            }
        }
    }
    if budget.remaining() < 60 {
        return Ok(false);
    }
    let view = plan::read_source(&store, env.shards, &source, &job.source_ref, &job.tip)
        .await
        .map_err(|e| {
            if e == ForkError::TipChanged {
                ForkError::NotFound
            } else {
                e
            }
        })?;
    if view.packmap != job.packmap
        || view.generation != job.source_generation
        || view.sequence != job.source_sequence
    {
        return Err(ForkError::NotFound);
    }
    if SourceAccessV1::read(&store, env.shards, &source).await? != job.source_access {
        return Err(ForkError::NotFound);
    }
    Ok(true)
}

/// The result, replay, and terminal outcome responsibility commit with acceptance.
pub(super) async fn commit<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
    now: u64,
) -> Result<Batch, ForkError> {
    // Registration serializes creation and every usable lease. No writer can
    // change authoritative emptiness while the operation owns that barrier.
    super::job::require_empty(env, &job.dest()?, true).await?;
    if !slice(env, job, budget).await? {
        return Ok(Batch::new());
    }
    job.accepted = Some(result(job)?);
    job.phase = super::Phase::Publish;
    job.cursor = 0;
    job.part = 0;
    let committed = super::settle::commit(env, job, now).await?;
    Ok(committed.require(Precondition::Equals(
        keys::fork_barrier(&job.dest()?.name),
        Value::new(job.binding.to_vec()),
    )))
}

pub(super) fn result(job: &ForkJobV1) -> Result<ForkResult, ForkError> {
    let source = job.source()?;
    Ok(ForkResult {
        source: crate::store::repo_storage::identity(&source.namespace, &source.name),
        source_ref: job.source_ref.clone(),
        tip: job.tip,
        source_sequence: job.source_sequence,
        packmap: job.packmap,
        pack_count: job.packs.len() as u64,
        pack_bytes: job.pack_bytes(),
        object_count: job.copied,
        pack_set: job.pack_set(),
        membership_generation: super::MEMBERSHIP_GENERATION,
    })
}
