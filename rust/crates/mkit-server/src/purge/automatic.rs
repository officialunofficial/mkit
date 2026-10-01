//! Shared automatic purge planning for serving-state mutations.
use super::{PurgeConfig, Request, Trigger, plan_enqueue};
use crate::store::keys;
use crate::{Batch, NamespaceStore, Partition, RepoId, StoreError};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};

pub(crate) fn repository_request(
    config: &PurgeConfig,
    partition: &Partition,
    repo: &RepoId,
    trigger: Trigger,
    operation_id: &str,
) -> Result<Request, StoreError> {
    let repository = format!("{}/{}", repo.namespace.as_str(), repo.name.as_str());
    let source = to_hex_bytes(&partition.encode()?);
    Ok(Request {
        purge_id: format!(
            "purge:{}",
            to_hex(&hash(
                format!(
                    "{}\0{repository}\0{source}\0{trigger:?}\0{operation_id}",
                    config.audience
                )
                .as_bytes()
            ))
        ),
        audience: config.audience.clone(),
        repository,
        namespace: String::new(),
        trigger,
        url_paths: Vec::new(),
        object_ids: Vec::new(),
        refs: Vec::new(),
    })
}

/// The caller merges every effect into its triggering state-change apply.
pub(crate) async fn plan_repository<S: NamespaceStore>(
    config: Option<&PurgeConfig>,
    store: &S,
    partition: &Partition,
    repo: &RepoId,
    trigger: Trigger,
    operation_id: &str,
    now: u64,
) -> Result<Batch, StoreError> {
    let Some(config) = config else {
        return Ok(Batch::new());
    };
    config.validate()?;
    let request = repository_request(config, partition, repo, trigger, operation_id)?;
    if let Some(existing) = super::read_request(store, partition, &request.purge_id).await? {
        if existing != request {
            return Err(StoreError::Corrupt(
                "automatic purge identity reused".into(),
            ));
        }
        // Acceptance/discovery retries retain the already durable responsibility.
        return Ok(Batch::new());
    }
    let audit = config
        .audit
        .as_ref()
        .ok_or_else(|| StoreError::Invalid("automatic purge requires durable audit".into()))?;
    let values = store
        .get_many(
            partition,
            &[
                keys::outcome_backlog(),
                keys::cache_purge_generation(request.scope()),
                keys::outbox_sequence(),
                keys::epoch_lease(),
            ],
        )
        .await?;
    if values.len() != 4 {
        return Err(StoreError::Corrupt("short automatic purge read".into()));
    }
    let lease = values[3]
        .clone()
        .filter(|_| matches!(partition, Partition::Ref { .. }));
    let deadline = lease
        .as_ref()
        .map(crate::store::codec::decode_epoch_lease)
        .transpose()?
        .map_or(now.saturating_add(30_000), |l| {
            now.saturating_add(30_000)
                .min(l.expires_at_ms.saturating_sub(1))
        });
    let snapshot = crate::relay::RelayEnqueueSnapshot {
        sequence: values[2].clone(),
        source_lease: lease,
        deadline_ms: deadline,
    };
    let mut batch = audit
        .plan(partition, &request, operation_id, now, snapshot)
        .await?;
    let work = plan_enqueue(&request, now, values[0].as_ref(), values[1].as_ref())?;
    batch.preconditions.extend(work.preconditions);
    batch.writes.extend(work.writes);
    Ok(batch)
}

/// Immediate best effort; committed timer 11 owns failures and partial deletion.
pub(crate) async fn invalidate_repository(
    config: Option<&PurgeConfig>,
    partition: &Partition,
    repo: &RepoId,
    trigger: Trigger,
    operation_id: &str,
    budget: &super::SliceBudget,
) {
    if let Some(config) = config
        && let Some(local) = &config.local
        && let Ok(request) = repository_request(config, partition, repo, trigger, operation_id)
    {
        let _ = local.invalidate(&request, 0, budget).await;
    }
}
