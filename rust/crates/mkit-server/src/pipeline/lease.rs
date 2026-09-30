//! D34 grants are observed before authorization and durably recorded only
//! after admission. Creation and renewal share one coordinator transaction.
//!
//! Outside a declared recovery hold-off, `ls.acked_epoch = n` means that el
//! durably holds epoch >= n, or every older-epoch write is past its deadline.
//! A live renewal preserves acknowledgement; only a committed revoke push can
//! raise it. During recovery, a rebuilt missing row can precede shard installation;
//! the lr hold-off fences completion until every surviving old deadline has passed.

use super::ShardMap;
use crate::op::{Creation, Operation};
use crate::quota::NamespaceUsage;
use crate::relay::relay_watermark;
use crate::repo::{Addressing, RepoId, RepoName};
use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, MultipartBlobStore, NamespaceStore, Partition, Precondition, StoreError,
    Value, codec, keys,
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
    Renew(Box<CoordinatorLease>),
}

pub(super) struct CoordinatorLease {
    namespace: Option<Value>,
    repo: Option<Value>,
    epoch: Option<Value>,
    authority: Option<Value>,
    authority_generation: Option<u64>,
    leased_epoch: u64,
    shard: Option<Value>,
    observed_el: Option<codec::EpochLease>,
    recovery: Option<codec::LeaseRecovery>,
    relay_watermark_ms: u64,
    quota_seed: Option<(u64, NamespaceUsage)>,
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
    pub(super) fn quota_seed(&self) -> Option<(u64, NamespaceUsage)> {
        match self {
            Self::Renew(read) => read.quota_seed,
            Self::Usable(_) => None,
        }
    }

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

// A source outbox scan precedes the coordinator read on renewal. Concurrent
// writers can therefore observe the same lease row before any grant commits.
// Keep grant retries local to this path; creation has a different retry bound.
const LEASE_GRANT_ATTEMPTS: usize = 8;

/// The lease timing a grant needs, apart from the rest of the pipeline's
/// configuration, so the relay seam ([`renew_for_relay`]) can run without a
/// pipeline. Defaults equal [`super::PipelineConfig::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseParams {
    /// Require the independent authority generation in the shared lease lifecycle.
    pub authority_fence: bool,
    /// Coordinator epoch lease duration, in milliseconds.
    pub epoch_lease_ms: u64,
    /// Clock-skew safety margin, in milliseconds.
    pub lease_margin_ms: u64,
    /// Minimum useful lease budget before renewing, in milliseconds.
    pub min_lease_budget_ms: u64,
}

impl Default for LeaseParams {
    fn default() -> Self {
        Self {
            authority_fence: false,
            epoch_lease_ms: 30_000,
            lease_margin_ms: 5_000,
            min_lease_budget_ms: 1_000,
        }
    }
}

impl From<&super::PipelineConfig> for LeaseParams {
    fn from(cfg: &super::PipelineConfig) -> Self {
        Self {
            authority_fence: cfg.authority_fence.is_some(),
            epoch_lease_ms: cfg.epoch_lease_ms,
            lease_margin_ms: cfg.lease_margin_ms,
            min_lease_budget_ms: cfg.min_lease_budget_ms,
        }
    }
}

#[allow(clippy::too_many_lines)] // One shared atomic grant guards both barriers and updates creation, lease and sweep rows.
fn grant_batch(
    read: &CoordinatorLease,
    repo: &RepoName,
    p: &Partition,
    now: u64,
    created_at_ms: u64,
    cfg: &LeaseParams,
) -> Result<LeaseGrant, ServerError> {
    let shard_ref = shard_ref(p)?;
    let ls_key = keys::leased_shard(repo, shard_ref);
    let reference = lease_reference(repo, shard_ref);
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
        authority_generation: read.authority_generation,
        acked_authority_generation: if old.is_some_and(|l| l.expires_at_ms > now) {
            old.and_then(|l| l.acked_authority_generation)
        } else {
            read.authority_generation
        },
        acked_epoch: old
            .filter(|l| l.expires_at_ms > now)
            .map_or(epoch, |l| l.acked_epoch),
        relay_watermark_ms: old
            .map_or(0, |l| l.relay_watermark_ms)
            .max(read.relay_watermark_ms),
        sweep_due_ms: old
            .map_or(0, |l| l.expires_at_ms)
            .max(now.saturating_add(cfg.epoch_lease_ms)),
    };
    let creation = read.creation();
    let nr_key = keys::namespace_record();
    let rr_key = keys::repo_record(repo);
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
    if read.authority_generation.is_some() {
        batch = batch.require(observed_guard(
            keys::authority_generation(),
            read.authority.as_ref(),
        ));
    }
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
            old.sweep_due_ms,
            kinds::LEASE_SWEEP.get(),
            &reference,
        ));
    }
    batch = batch
        .put(ls_key.clone(), codec::encode_leased_shard(&shard))
        .put(
            keys::timer(shard.sweep_due_ms, kinds::LEASE_SWEEP.get(), &reference),
            Value::default(),
        );
    let value = codec::EpochLease {
        epoch,
        authority_generation: read.authority_generation,
        expires_at_ms: shard.expires_at_ms,
        config_version: namespace.config_version,
    };
    Ok(LeaseGrant {
        creation,
        value,
        batch,
    })
}

/// Read the coordinator rows a grant plans from and the shard's relay
/// watermark. `source` serves the ref shard `p`; `coordinator_store` the
/// namespace coordinator (the same store, except on a Worker's timer).
#[allow(clippy::too_many_arguments)]
async fn read_lease_rows<L: NamespaceStore, M: NamespaceStore>(
    source: &L,
    coordinator_store: &M,
    shards: &dyn ShardMap,
    clock: &dyn Clock,
    repo_id: &RepoId,
    p: &Partition,
    observed_el: Option<codec::EpochLease>,
    seed_window: Option<u64>,
    authority_fence: bool,
) -> Result<CoordinatorLease, ServerError> {
    let mut wanted = vec![
        keys::namespace_record(),
        keys::repo_record(&repo_id.name),
        keys::grant_epoch(),
        keys::leased_shard(&repo_id.name, shard_ref(p)?),
        keys::lease_recovery(),
    ];
    let authority_fence =
        authority_fence || observed_el.is_some_and(|el| el.authority_generation.is_some());
    if authority_fence {
        wanted.push(keys::authority_generation());
    }
    if let Some(window) = seed_window {
        wanted.push(keys::quota_total(window));
    }
    let reported = match relay_watermark(source, p, ms(clock.now_ms())).await {
        Ok(value) => value,
        Err(StoreError::Corrupt(reason)) => {
            tracing::warn!(shard = ?p, %reason, "renewal cannot decode relay outbox; reporting zero");
            0
        }
        Err(error) => return Err(meta_error(error)),
    };
    let rows = coordinator_store
        .get_many(&shards.coordinator(&repo_id.namespace), &wanted)
        .await
        .map_err(meta_error)?;
    if rows.len() != wanted.len() {
        return Err(internal("lease get_many returned the wrong row count"));
    }
    let [namespace, repo, epoch, shard, recovery] = &rows[..5] else {
        return Err(internal("lease get_many returned the wrong row count"));
    };
    let authority = if authority_fence {
        rows[5].clone()
    } else {
        None
    };
    let quota_seed = seed_window
        .map(|window| {
            rows[5 + usize::from(authority_fence)]
                .as_ref()
                .map(codec::decode_namespace_usage)
                .transpose()
                .map(|total| (window, total.unwrap_or_default()))
                .map_err(meta_error)
        })
        .transpose()?;
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
        authority: authority.clone(),
        authority_generation: if authority_fence {
            Some(
                authority
                    .as_ref()
                    .map(codec::decode_u64)
                    .transpose()
                    .map_err(meta_error)?
                    .unwrap_or(0),
            )
        } else {
            None
        },
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
        relay_watermark_ms: reported,
        quota_seed,
    };
    Ok(read)
}

/// Least remaining lease (before the margin) a relay enqueue needs: its own
/// commit deadline and the margin fit in it.
const RELAY_LEASE_BUDGET_MS: u64 = 15_000;

/// The source epoch lease for an index relay enqueue that a timer performs,
/// not an `AdvanceRefs` (WP-4.8, D-1). The lease lasts 30 s and a decode
/// slice can outlast it, but only pipeline batches renew and install it. This
/// runs the same coordinator transaction as `Pipeline::admit_lease` (the one
/// `grant_batch`, so `ls` and `acked_epoch` follow the advance's rules) and
/// installs `el` in its own batch guarded by the value it observed, instead of
/// in an advance batch. A lease with `RELAY_LEASE_BUDGET_MS` left is
/// returned as it is. The raw value is what the relay batches guard; a batch
/// that loses the lease fails, it does not commit.
///
/// `local` serves the ref shard `p`; `meta` the coordinator.
///
/// # Errors
/// A mapped storage error, or `aborted` after repeated contention.
pub async fn renew_for_relay<L: NamespaceStore, M: NamespaceStore>(
    local: &L,
    meta: &M,
    shards: &dyn ShardMap,
    clock: &dyn Clock,
    repo: &RepoId,
    p: &Partition,
    params: &LeaseParams,
) -> Result<Value, ServerError> {
    for _ in 0..LEASE_GRANT_ATTEMPTS {
        let raw = local
            .get(p, &keys::epoch_lease())
            .await
            .map_err(meta_error)?;
        let observed = raw
            .as_ref()
            .map(codec::decode_epoch_lease)
            .transpose()
            .map_err(meta_error)?;
        let now = ms(clock.now_ms());
        if let (Some(raw), Some(lease)) = (&raw, observed)
            && (!params.authority_fence || lease.authority_generation.is_some())
            && lease
                .expires_at_ms
                .checked_sub(params.lease_margin_ms)
                .and_then(|end| end.checked_sub(now))
                .is_some_and(|budget| budget >= RELAY_LEASE_BUDGET_MS)
        {
            return Ok(raw.clone());
        }
        let read = read_lease_rows(
            local,
            meta,
            shards,
            clock,
            repo,
            p,
            observed,
            None,
            params.authority_fence,
        )
        .await?;
        let grant = grant_batch(&read, &repo.name, p, now, now, params)?;
        match meta
            .apply(&shards.coordinator(&repo.namespace), grant.batch)
            .await
            .map_err(meta_error)?
        {
            BatchOutcome::Committed => {}
            BatchOutcome::PreconditionFailed { .. } => continue,
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(internal("lease grant had no deadline"));
            }
        }
        let value = codec::encode_epoch_lease(&grant.value);
        let install = Batch::new()
            .require(Precondition::NotAfter(now.saturating_add(10_000)))
            .require(observed_guard(keys::epoch_lease(), raw.as_ref()))
            .put(keys::epoch_lease(), value.clone());
        if matches!(
            local.apply(p, install).await.map_err(meta_error)?,
            BatchOutcome::Committed
        ) {
            return Ok(value);
        }
    }
    Err(ServerError::aborted_retryable(
        "coordinator lease grant contention",
    ))
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn observe_lease(
        &self,
        op: &Operation,
        p: &Partition,
        ahead: Option<&Snapshot>,
    ) -> Result<LeaseObservation, ServerError> {
        let snap = ahead.ok_or_else(|| internal("D34 lease requires an atomic snapshot"))?;
        let seed_window = snap.namespace_window.filter(|window| {
            let key = keys::quota_view(*window);
            snap.contains(&key) && snap.get(&key).is_none()
        });
        let observed_el = snap
            .get(&keys::epoch_lease())
            .map(codec::decode_epoch_lease)
            .transpose()
            .map_err(meta_error)?;
        if let Some(lease) = observed_el.filter(|lease| {
            self.cfg.authority_fence.is_none() || lease.authority_generation.is_some()
        }) {
            let now = ms(self.clock.now_ms());
            let usable_until = lease.expires_at_ms.checked_sub(self.cfg.lease_margin_ms);
            if usable_until
                .and_then(|end| end.checked_sub(now))
                .is_some_and(|budget| budget >= self.cfg.min_lease_budget_ms)
            {
                return Ok(LeaseObservation::Usable(lease));
            }
        }
        Ok(LeaseObservation::Renew(Box::new(
            self.read_lease(op, p, observed_el, seed_window).await?,
        )))
    }

    async fn read_lease(
        &self,
        op: &Operation,
        p: &Partition,
        observed_el: Option<codec::EpochLease>,
        seed_window: Option<u64>,
    ) -> Result<CoordinatorLease, ServerError> {
        read_lease_rows(
            &self.meta,
            &self.meta,
            self.shards.as_ref(),
            self.clock.as_ref(),
            &op.repo,
            p,
            observed_el,
            seed_window,
            self.cfg.authority_fence.is_some(),
        )
        .await
    }

    pub(super) async fn admit_lease(
        &self,
        op: &Operation,
        p: &Partition,
        observed: LeaseObservation,
        skew_ms: i64,
    ) -> Result<(Creation, LeaseWrite), ServerError> {
        let LeaseObservation::Renew(read) = observed else {
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
        let mut read = *read;
        let coordinator = self.shards.coordinator(&op.repo.namespace);
        for _ in 0..LEASE_GRANT_ATTEMPTS {
            if op
                .authz
                .grant
                .as_ref()
                .is_some_and(|grant| grant.epoch != read.leased_epoch)
            {
                return Err(super::plan::epoch_moved());
            }
            if let Some(generation) = op.authz.authority_generation
                && Some(generation) != read.authority_generation
            {
                return Err(crate::authority::moved());
            }
            let now = ms(self.clock.now_ms());
            let created_at_ms = ms(self.clock.now_ms().saturating_add(skew_ms));
            let grant = grant_batch(
                &read,
                &op.repo.name,
                p,
                now,
                created_at_ms,
                &LeaseParams::from(&self.cfg),
            )?;
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
                    read = self
                        .read_lease(op, p, read.observed_el, read.quota_seed.map(|(w, _)| w))
                        .await?;
                }
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("lease grant had no deadline"));
                }
            }
        }
        tracing::warn!(shard = ?p, attempts = LEASE_GRANT_ATTEMPTS, "coordinator lease grant did not settle");
        Err(ServerError::aborted_retryable(
            "coordinator lease grant contention",
        ))
    }
}

#[cfg(test)]
#[path = "lease_model_tests.rs"]
mod model_tests;
