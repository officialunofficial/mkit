//! Durable dependency rechecks. One retained timer per blocked advance avoids
//! an unbounded reverse-dependency fanout when membership publishes across refs.
use crate::pipeline::{D34Shards, ShardMap, SinglePartition};
use crate::repo::RepoId;
use crate::rt::BoxFuture;
use crate::store::outbox::OutboxBuilder;
use crate::store::publication::{self, Advance, Clearance, Publication, Witness};
use crate::store::{
    Batch, BlobKey, Key, NamespaceStore, Partition, Precondition, StoreError, Value, keys,
};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use std::collections::BTreeMap;

/// Maximum routed witness reads per fire. Together with relay (512),
/// verification (256), outcomes (64), rollup (32) and backup (1), this uses
/// at most 993 of the existing 1,000-operation Paid alarm allowance.
pub const MAX_RECHECK_CALLS: u32 = 128;
const REMOTE_PAGE_KEYS: usize = 8;
const LOCAL_PAGE_KEYS: usize = 256;

/// One retained timer resumes a canonical dependency walk across alarms.
pub struct PublicationRecheck<T> {
    /// Routed metadata client for dependency witnesses outside the source shard.
    pub target: T,
}

/// A recheck sharing its caller's whole-alarm allowance.
#[derive(Debug)]
pub struct BudgetedRecheck<T> {
    recheck: PublicationRecheck<T>,
    budget: crate::purge::SliceBudget,
}

impl<T> PublicationRecheck<T> {
    /// Construct a recheck with the fixed routed-call cap.
    pub fn new(target: T) -> Self {
        Self { target }
    }

    /// Reserve shared operations before routed reads. The target must not
    /// charge the same allowance again; source-local SQL calls are separate.
    #[must_use]
    pub fn with_alarm_budget(self, budget: crate::purge::SliceBudget) -> BudgetedRecheck<T> {
        BudgetedRecheck {
            recheck: self,
            budget,
        }
    }
}

// The current timer codec is fixed-width: version, bound row digest, then
// the next routed witness ordinal in little endian. No pre-launch migration.
#[derive(Debug, Default, PartialEq, Eq)]
struct Progress {
    binding: mkit_core::hash::Hash,
    position: u32,
}
impl Progress {
    fn decode(value: &Value) -> Result<Self, StoreError> {
        let bytes = value.as_bytes();
        if bytes.len() != 37 || bytes[0] != 1 {
            return Err(StoreError::Corrupt(
                "invalid publication recheck cursor".into(),
            ));
        }
        let binding = bytes[1..33]
            .try_into()
            .map_err(|_| StoreError::Corrupt("invalid recheck binding".into()))?;
        let position = u32::from_le_bytes(
            bytes[33..]
                .try_into()
                .map_err(|_| StoreError::Corrupt("invalid recheck position".into()))?,
        );
        if position > 8192 {
            return Err(StoreError::Corrupt(
                "publication recheck position exceeds bound".into(),
            ));
        }
        Ok(Self { binding, position })
    }
    fn encode(&self) -> Value {
        let mut bytes = Vec::with_capacity(37);
        bytes.push(1);
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&self.position.to_le_bytes());
        Value::new(bytes)
    }
    fn bind(&mut self, advance: &Value, state: &Publication) {
        let mut digest = mkit_core::hash::Hasher::new();
        digest.update(&state.generation.to_le_bytes());
        digest.update(&state.boundary.to_le_bytes());
        digest.update(advance.as_bytes());
        let binding = digest.finalize();
        if self.binding != binding {
            self.binding = binding;
            self.position = 0;
        }
    }
}

/// Initial value written atomically with a retained pending advance.
pub(crate) fn initial_value() -> Value {
    Progress::default().encode()
}

fn dependency_groups(
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &Advance,
) -> BTreeMap<Partition, Vec<Key>> {
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
    groups
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
    let groups = dependency_groups(source, shards, repo, advance);
    for (p, keys) in groups {
        for page in keys.chunks(8) {
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

async fn visible_rows<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    keys: &[Key],
) -> Result<Vec<Option<Value>>, StoreError> {
    let rows = store.get_many(partition, keys).await?;
    if rows.len() != keys.len() {
        return Err(StoreError::Corrupt(
            "short publication dependency read".into(),
        ));
    }
    // Decode before advancing the cursor; missing/nonvisible rows are handled
    // individually below, so no later row in a page skips an outstanding one.
    for raw in rows.iter().flatten() {
        Witness::decode(raw)?;
    }
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
async fn resume_dependencies<S: NamespaceStore, T: NamespaceStore>(
    local: &S,
    target: &T,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &Advance,
    progress: &mut Progress,
    alarm_budget: Option<&crate::purge::SliceBudget>,
) -> Result<bool, StoreError> {
    let groups = dependency_groups(source, shards, repo, advance);
    let needed = groups
        .iter()
        .filter(|(p, _)| *p != source)
        .map(|(_, keys)| keys.len())
        .sum::<usize>();
    let position = usize::try_from(progress.position)
        .map_err(|_| StoreError::Corrupt("invalid recheck position".into()))?;
    if position > needed {
        return Err(StoreError::Corrupt(
            "publication recheck position exceeds dependencies".into(),
        ));
    }
    // Unlike launch pm projections, source-local membership can be replaced
    // by pending additions. Never cache its visibility across fires.
    if let Some(keys) = groups.get(source) {
        for page in keys.chunks(LOCAL_PAGE_KEYS) {
            let rows = visible_rows(local, source, page).await?;
            for raw in rows {
                if raw
                    .as_ref()
                    .map(Witness::decode)
                    .transpose()?
                    .is_none_or(|w| !w.visible(false, advance.generation))
                {
                    return Ok(false);
                }
            }
        }
    }
    let mut offset = 0;
    let mut calls = 0;
    for (partition, keys) in groups.iter().filter(|(p, _)| *p != source) {
        let skip = position.saturating_sub(offset).min(keys.len());
        offset += keys.len();
        for page in keys[skip..].chunks(REMOTE_PAGE_KEYS) {
            if calls == MAX_RECHECK_CALLS || alarm_budget.is_some_and(|budget| !budget.charge(1)) {
                return Ok(false);
            }
            calls += 1;
            let rows = visible_rows(target, partition, page).await?;
            for raw in rows {
                if raw
                    .as_ref()
                    .map(Witness::decode)
                    .transpose()?
                    .is_none_or(|w| !w.visible(false, advance.generation))
                {
                    return Ok(false);
                }
                progress.position += 1;
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
        self.fire_inner(ctx, timer, None)
    }
}

impl<S: NamespaceStore, T: NamespaceStore> TimerHandler<S> for BudgetedRecheck<T> {
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
        self.recheck.fire_inner(ctx, timer, Some(&self.budget))
    }
}

impl<T: NamespaceStore> PublicationRecheck<T> {
    fn fire_inner<'a, S: NamespaceStore>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
        alarm_budget: Option<&'a crate::purge::SliceBudget>,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let mut progress = Progress::decode(&timer.value)?;
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
            progress.bind(raw, &state);
            let mut batch =
                Batch::new().require(Precondition::NotAfter(ctx.now_ms.saturating_add(10_000)));
            let eligible = changed.generation == state.generation
                && (changed.state == Clearance::Pending || changed.state.publishable())
                && changed.obligations.iter().all(|o| o.state.publishable());
            let complete = if eligible {
                resume_dependencies(
                    ctx.store,
                    &self.target,
                    ctx.partition,
                    shards,
                    &repo,
                    &changed,
                    &mut progress,
                    alarm_budget,
                )
                .await?
            } else {
                // A hold/hit or outstanding obligation never becomes cleared by
                // the timer. If it is later released, check every witness afresh.
                progress.position = 0;
                false
            };
            if !complete || changed.state.publishable() {
                batch.preconditions.extend([
                    Precondition::Equals(key, raw.clone()),
                    Precondition::Equals(wanted[1].clone(), state_raw.clone()),
                ]);
                if !complete {
                    return Ok(Fired::Reschedule {
                        due_at_ms: ctx.now_ms.saturating_add(publication::RECHECK_MS),
                        value: progress.encode(),
                        batch,
                    });
                }
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

#[cfg(test)]
mod tests;
