//! D34 grants are observed before authorization and durably recorded only
//! after admission. Creation and renewal share one coordinator transaction.
//!
//! Outside a declared recovery hold-off, `ls.acked_epoch = n` means that el
//! durably holds epoch >= n, or every older-epoch write is past its deadline.
//! A live renewal preserves acknowledgement; only a committed revoke push can
//! raise it. During recovery, a rebuilt missing row can precede shard installation;
//! the lr hold-off fences completion until every surviving old deadline has passed.

use crate::op::{Creation, Operation};
use crate::repo::Addressing;
use crate::store::{
    Batch, BatchOutcome, MultipartBlobStore, NamespaceStore, Partition, Precondition, Value, codec,
    keys,
};
use crate::timers::lease_sweep::lease_reference;
use crate::timers::registry::kinds;

use super::{HookSet, Pipeline, Snapshot, internal, meta_error, ms};
use crate::error::ServerError;

/// What the ref batch guards and, after renewal, installs atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LeaseWrite {
    pub(super) value: codec::EpochLease,
    pub(super) install: bool,
}

pub(super) enum LeaseObservation {
    Usable(codec::EpochLease),
    Renew(CoordinatorLease),
}

pub(super) struct CoordinatorLease {
    namespace: Option<Value>,
    repo: Option<Value>,
    epoch: Option<Value>,
    leased_epoch: u64,
    shard: Option<Value>,
    observed_el: Option<codec::EpochLease>,
    recovery: Option<codec::LeaseRecovery>,
}

impl CoordinatorLease {
    fn creation(&self) -> Creation {
        Creation {
            namespace: self.namespace.is_none(),
            repo: self.repo.is_none(),
        }
    }

    fn epoch(&self) -> u64 {
        self.leased_epoch
    }
}

impl LeaseObservation {
    pub(super) fn creation(&self, addressing: &Addressing) -> Creation {
        match self {
            Self::Renew(read) if matches!(addressing, Addressing::Multi(_)) => read.creation(),
            _ => Creation::default(),
        }
    }

    pub(super) fn epoch(&self) -> u64 {
        match self {
            Self::Usable(lease) => lease.epoch,
            Self::Renew(read) => read.epoch(),
        }
    }
}

pub(super) fn observed_guard(key: crate::store::Key, value: Option<&Value>) -> Precondition {
    match value {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

fn shard_ref(p: &Partition) -> Result<&str, ServerError> {
    match p {
        Partition::Ref { shard_ref, .. } => Ok(shard_ref),
        _ => Err(internal("epoch lease outside a ref shard")),
    }
}

struct LeaseGrant {
    creation: Creation,
    value: codec::EpochLease,
    batch: Batch,
}

fn grant_batch(
    read: &CoordinatorLease,
    op: &Operation,
    p: &Partition,
    now: u64,
    created_at_ms: u64,
    cfg: &super::PipelineConfig,
) -> Result<LeaseGrant, ServerError> {
    let shard_ref = shard_ref(p)?;
    let ls_key = keys::leased_shard(&op.repo.name, shard_ref);
    let reference = lease_reference(&op.repo.name, shard_ref);
    let epoch = read.epoch();
    let old = read
        .shard
        .as_ref()
        .map(codec::decode_leased_shard)
        .transpose()
        .map_err(meta_error)?;
    // A declared recovery can leave a surviving el without its lease-table row.
    // Completion remains fenced by the same hold-off in revoke_step.
    let recovering = read.recovery.is_some_and(|lr| {
        now < lr
            .resumed_at_ms
            .saturating_add(cfg.epoch_lease_ms)
            .saturating_add(cfg.lease_margin_ms)
    });
    if !recovering && old.is_none_or(|lease| lease.expires_at_ms <= now) {
        let observed_ls_expires = old.map_or(0, |lease| lease.expires_at_ms);
        // Safety relies on lease_margin_ms exceeding every clock skew
        // (see PipelineConfig::lease_margin_ms).
        debug_assert!(
            read.observed_el.is_none_or(|el| el.expires_at_ms
                <= observed_ls_expires
                    .max(now)
                    .saturating_add(cfg.lease_margin_ms)),
            "an observed el outlives every ls it could have been granted under, beyond the skew margin"
        );
    }
    let shard = codec::LeasedShard {
        epoch,
        expires_at_ms: old
            .map_or(0, |l| l.expires_at_ms)
            .max(now.saturating_add(cfg.epoch_lease_ms)),
        acked_epoch: old
            .filter(|l| l.expires_at_ms > now)
            .map_or(epoch, |l| l.acked_epoch),
    };
    let creation = read.creation();
    let nr_key = keys::namespace_record();
    let rr_key = keys::repo_record(&op.repo.name);
    let namespace = match &read.namespace {
        Some(value) => codec::decode_namespace_record(value).map_err(meta_error)?,
        None => codec::NamespaceRecord {
            created_at_ms,
            config_version: 1,
        },
    };
    let mut batch = Batch::new()
        .require(if creation.namespace {
            Precondition::Absent(nr_key.clone())
        } else {
            Precondition::Present(nr_key.clone())
        })
        .require(if creation.repo {
            Precondition::Absent(rr_key.clone())
        } else {
            Precondition::Present(rr_key.clone())
        })
        .require(observed_guard(keys::grant_epoch(), read.epoch.as_ref()))
        .require(observed_guard(ls_key.clone(), read.shard.as_ref()));
    if creation.namespace {
        batch = batch.put(nr_key, codec::encode_namespace_record(&namespace));
    }
    if creation.repo {
        batch = batch.put(
            rr_key,
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms }),
        );
    }
    if let Some(old) = old {
        batch = batch.delete(keys::timer(
            old.expires_at_ms,
            kinds::LEASE_SWEEP.get(),
            &reference,
        ));
    }
    batch = batch
        .put(ls_key.clone(), codec::encode_leased_shard(&shard))
        .put(
            keys::timer(shard.expires_at_ms, kinds::LEASE_SWEEP.get(), &reference),
            Value::default(),
        );
    let value = codec::EpochLease {
        epoch,
        expires_at_ms: shard.expires_at_ms,
        config_version: namespace.config_version,
    };
    Ok(LeaseGrant {
        creation,
        value,
        batch,
    })
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn observe_lease(
        &self,
        op: &Operation,
        p: &Partition,
        ahead: Option<&Snapshot>,
    ) -> Result<LeaseObservation, ServerError> {
        let snap = ahead.ok_or_else(|| internal("D34 lease requires an atomic snapshot"))?;
        let observed_el = snap
            .get(&keys::epoch_lease())
            .map(codec::decode_epoch_lease)
            .transpose()
            .map_err(meta_error)?;
        if let Some(lease) = observed_el {
            let now = ms(self.clock.now_ms());
            let usable_until = lease.expires_at_ms.checked_sub(self.cfg.lease_margin_ms);
            if usable_until
                .and_then(|end| end.checked_sub(now))
                .is_some_and(|budget| budget >= self.cfg.min_lease_budget_ms)
            {
                return Ok(LeaseObservation::Usable(lease));
            }
        }
        Ok(LeaseObservation::Renew(
            self.read_lease(op, p, observed_el).await?,
        ))
    }

    async fn read_lease(
        &self,
        op: &Operation,
        p: &Partition,
        observed_el: Option<codec::EpochLease>,
    ) -> Result<CoordinatorLease, ServerError> {
        let wanted = [
            keys::namespace_record(),
            keys::repo_record(&op.repo.name),
            keys::grant_epoch(),
            keys::leased_shard(&op.repo.name, shard_ref(p)?),
            keys::lease_recovery(),
        ];
        let rows = self
            .meta
            .get_many(&self.shards.coordinator(&op.repo.namespace), &wanted)
            .await
            .map_err(meta_error)?;
        let [namespace, repo, epoch, shard, recovery] = rows.as_slice() else {
            return Err(internal("lease get_many returned the wrong row count"));
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
        if let Some(value) = shard {
            codec::decode_leased_shard(value).map_err(meta_error)?;
        }
        let read = CoordinatorLease {
            namespace: namespace.clone(),
            repo: repo.clone(),
            epoch: epoch.clone(),
            leased_epoch: epoch
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0),
            shard: shard.clone(),
            observed_el,
            recovery: recovery
                .as_ref()
                .map(codec::decode_lease_recovery)
                .transpose()
                .map_err(meta_error)?,
        };
        Ok(read)
    }

    pub(super) async fn admit_lease(
        &self,
        op: &Operation,
        p: &Partition,
        observed: LeaseObservation,
        skew_ms: i64,
    ) -> Result<(Creation, LeaseWrite), ServerError> {
        let LeaseObservation::Renew(mut read) = observed else {
            let LeaseObservation::Usable(value) = observed else {
                unreachable!()
            };
            return Ok((
                Creation::default(),
                LeaseWrite {
                    value,
                    install: false,
                },
            ));
        };
        // TODO(WP-2.6): compare grant.epoch with the observed coordinator e before
        // writing a lease grant, so stale-grant denial writes no state (STC §5.1).
        let coordinator = self.shards.coordinator(&op.repo.namespace);
        for _ in 0..super::coordinator::CREATION_ATTEMPTS {
            let now = ms(self.clock.now_ms());
            let created_at_ms = ms(self.clock.now_ms().saturating_add(skew_ms));
            let grant = grant_batch(&read, op, p, now, created_at_ms, &self.cfg)?;
            match self
                .meta
                .apply(&coordinator, grant.batch)
                .await
                .map_err(meta_error)?
            {
                BatchOutcome::Committed => {
                    let created = if matches!(self.cfg.addressing, Addressing::Multi(_)) {
                        grant.creation
                    } else {
                        Creation::default()
                    };
                    return Ok((
                        created,
                        LeaseWrite {
                            value: grant.value,
                            install: true,
                        },
                    ));
                }
                BatchOutcome::PreconditionFailed { .. } => {
                    read = self.read_lease(op, p, read.observed_el).await?;
                }
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("lease grant had no deadline"));
                }
            }
        }
        Err(internal("coordinator lease grant did not settle"))
    }
}

#[cfg(test)]
#[path = "lease_model_tests.rs"]
mod model_tests;
