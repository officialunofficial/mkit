//! Durable dependency rechecks. One retained timer per blocked advance avoids
//! an unbounded reverse-dependency fanout when membership publishes across refs.
use crate::pipeline::{D34Shards, ShardMap, SinglePartition};
use crate::repo::RepoId;
use crate::rt::BoxFuture;
use crate::store::outbox::OutboxBuilder;
use crate::store::publication::{self, Advance, Clearance, Publication, Witness};
use crate::store::{
    Batch, BlobKey, Key, NamespaceStore, Partition, Precondition, StoreError, keys,
};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use std::collections::BTreeMap;

/// One dependency page is at most 256 keys. An advance retains at most 4096
/// closure packs and 4096 external bases; one fire makes at most 8192 target
/// calls in the worst hash distribution. Worker activation is Paid only, with one fire per alarm. This stays below
/// the 10,000-call budget alongside relay (512), verification (256), outcome
/// (64), rollup (8) and snapshot work.
pub struct PublicationRecheck<T> {
    /// Routed metadata client for dependency witnesses outside the source shard.
    pub target: T,
}
impl<T> core::fmt::Debug for PublicationRecheck<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicationRecheck").finish_non_exhaustive()
    }
}

/// Verify published dependencies against current versioned witnesses. Own
/// additions satisfy closure, but never external delta-base dependencies.
/// Missing/reordered projections reduce visibility. Corruption fails closed.
pub async fn dependencies<S: NamespaceStore, T: NamespaceStore>(
    local: &S,
    target: &T,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &Advance,
) -> Result<bool, StoreError> {
    let mut needed = advance
        .dependencies
        .iter()
        .filter(|id| !advance.additions.contains(id))
        .chain(advance.external_bases.iter())
        .copied()
        .collect::<Vec<_>>();
    needed.sort_unstable();
    needed.dedup();
    let mut groups: BTreeMap<Partition, Vec<Key>> = BTreeMap::new();
    for pack in needed {
        let p = shards.membership(repo, &BlobKey::pack(pack));
        let key = if p == *source {
            keys::membership(&repo.name, &pack)
        } else {
            keys::published_member(&repo.name, &pack)
        };
        groups.entry(p).or_default().push(key);
    }
    for (p, keys) in groups {
        for page in keys.chunks(256) {
            let rows = if p == *source {
                local.get_many(&p, page).await?
            } else {
                target.get_many(&p, page).await?
            };
            if rows.len() != page.len() {
                return Err(StoreError::Corrupt(
                    "short publication dependency read".into(),
                ));
            }
            for raw in rows {
                let Some(raw) = raw else { return Ok(false) };
                if !Witness::decode(&raw)?.visible(false, advance.generation) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn location(
    partition: &Partition,
    key: &Key,
) -> Result<(RepoId, String, u64, &'static dyn ShardMap), StoreError> {
    let Some(keys::ParsedKey::Advance {
        repo,
        name,
        sequence,
    }) = keys::parse(key)
    else {
        return Err(StoreError::Corrupt(
            "invalid publication timer reference".into(),
        ));
    };
    let ns = match partition {
        Partition::Namespace(ns) | Partition::Ref { ns, .. } => ns.clone(),
        _ => {
            return Err(StoreError::Corrupt(
                "publication timer on wrong partition".into(),
            ));
        }
    };
    let repo = RepoId {
        namespace: ns,
        name: repo,
    };
    let shards: &dyn ShardMap = if matches!(partition, Partition::Namespace(_)) {
        &SinglePartition
    } else {
        &D34Shards
    };
    if shards.ref_shard(&repo, &name) != *partition {
        return Err(StoreError::Corrupt("misrouted publication timer".into()));
    }
    Ok((repo, name, sequence, shards))
}

impl<S: NamespaceStore, T: NamespaceStore> TimerHandler<S> for PublicationRecheck<T> {
    fn kind(&self) -> TimerKind {
        kinds::PUBLICATION_RECHECK
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let key = Key::new(timer.reference.clone());
            let (repo, name, sequence, shards) = location(ctx.partition, &key)?;
            let wanted = [
                key.clone(),
                keys::publication(&repo.name, &name),
                keys::outbox_sequence(),
                keys::outcome_backlog(),
            ];
            let rows = ctx.store.get_many(ctx.partition, &wanted).await?;
            if rows.len() != wanted.len() {
                return Err(StoreError::Corrupt("short publication recheck read".into()));
            }
            let raw = rows[0]
                .as_ref()
                .ok_or_else(|| StoreError::Corrupt("missing retained publication work".into()))?;
            let mut changed = Advance::decode(raw)?;
            let state_raw = rows[1]
                .as_ref()
                .ok_or_else(|| StoreError::Corrupt("missing publication state".into()))?;
            let state = Publication::decode(Some(state_raw))?;
            if changed.sequence != sequence {
                return Err(StoreError::Corrupt(
                    "publication timer sequence mismatch".into(),
                ));
            }
            let mut batch =
                Batch::new().require(Precondition::NotAfter(ctx.now_ms.saturating_add(10_000)));
            // A hold/hit has no automatic completion. Neither unavailable nor
            // the passage of time waives an obligation or takedown.
            if changed.generation != state.generation
                || !(changed.state == Clearance::Pending || changed.state.publishable())
                || changed.obligations.iter().any(|o| !o.state.publishable())
                || !dependencies(
                    ctx.store,
                    &self.target,
                    ctx.partition,
                    shards,
                    &repo,
                    &changed,
                )
                .await?
            {
                batch
                    .preconditions
                    .push(Precondition::Equals(key, raw.clone()));
                return Ok(Fired::Reschedule {
                    due_at_ms: ctx.now_ms.saturating_add(publication::RECHECK_MS),
                    value: timer.value.clone(),
                    batch,
                });
            }
            if changed.state.publishable() {
                batch.preconditions.extend([
                    Precondition::Equals(key, raw.clone()),
                    Precondition::Equals(wanted[1].clone(), state_raw.clone()),
                ]);
                return Ok(Fired::Done(batch));
            }
            changed.state = Clearance::Cleared;
            let eligible = publication::prefix(
                ctx.store,
                ctx.partition,
                &repo.name,
                &name,
                &state,
                &changed,
            )
            .await?;
            let mut outbox = OutboxBuilder::new(rows[2].as_ref(), rows[3].as_ref())?;
            publication::clear(
                &repo,
                &name,
                ctx.partition,
                shards,
                state_raw,
                raw,
                &changed,
                eligible,
                &mut batch.preconditions,
                &mut batch.writes,
                &mut outbox,
            )?;
            outbox.relay_at(ctx.now_ms);
            outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;
            Ok(Fired::Done(batch))
        })
    }
}
