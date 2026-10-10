//! The pack set: which of the source's packs the destination inherits.
//!
//! Starting from the published packmap head, a pack set is closed under
//! three relations, all read from sealed inventories (global, immutable):
//! a packmap node names its predecessor and its listed packs, and a data pack
//! names the external delta bases it lacks. Each external base object is
//! mapped to the source pack that holds it.

use super::{ForkEnv, ForkError, ForkJobV1, PackRow};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::repo::RepoId;
use crate::store::publication::{self, Witness};
use crate::store::{BlobKey, NamespaceStore, index, keys};
use crate::takedown::inventory;
use mkit_core::hash::Hash;
use std::collections::BTreeSet;

/// The reserve one unit of plan work needs before it starts: a pack's checks
/// plus up to 250 dependency-scan calls.
const UNIT_RESERVE: u32 = 300;

/// The published pair read from the source in one step.
pub(crate) struct SourceView {
    pub packmap: Hash,
    pub sequence: u64,
    pub generation: u64,
}

/// Read the source's published value for `source_ref` and compare it with the
/// caller's expected tip. A missing, unpublished or unpaired ref is not found;
/// a different tip is the only distinguishable source-side answer.
pub(crate) async fn read_source<S: NamespaceStore>(
    store: &S,
    shards: &dyn crate::pipeline::ShardMap,
    source: &RepoId,
    source_ref: &str,
    expected: &Hash,
) -> Result<SourceView, ForkError> {
    if !source_ref.starts_with("refs/heads/") || !crate::refs::validate_ref_name(source_ref) {
        return Err(ForkError::NotFound);
    }
    let p = shards.ref_shard(source, source_ref);
    let row = publication::read(store, &p, &source.name, source_ref).await?;
    match (row.value.head, row.value.packmap) {
        (Some(head), Some(packmap)) if head == *expected => Ok(SourceView {
            packmap,
            sequence: row.sequence,
            generation: row.generation,
        }),
        (Some(_), Some(_)) => Err(ForkError::TipChanged),
        _ => Err(ForkError::NotFound),
    }
}

/// Run plan units until the slice budget is spent or the set is complete.
/// `true` when the plan is complete and within bounds.
pub(crate) async fn slice<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    let source = job.source()?;
    let store = Budgeted::new(env.store, budget);
    // A slice that never got a full allowance only yields; one that had it
    // and still cannot finish a unit has met a bound of the implementation.
    let fresh = super::fresh(budget);
    let mut progressed = false;
    loop {
        if budget.remaining() < UNIT_RESERVE {
            return Ok(false);
        }
        let result = if (job.cursor as usize) < job.packs.len() {
            inspect(env, &store, budget, job, &source).await
        } else if !job.deps.is_empty() {
            resolve(&store, env, job, &source).await
        } else {
            return Ok(true);
        };
        match result {
            Ok(()) => progressed = true,
            Err(error) if super::spent(&error, budget) => {
                return if progressed || !fresh {
                    Ok(false)
                } else {
                    Err(ForkError::TooLarge)
                };
            }
            Err(error) => return Err(error),
        }
        if job.packs.len() > env.limits.max_packs || job.object_total() > env.limits.max_objects {
            return Err(ForkError::TooLarge);
        }
    }
}

async fn inspect<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    budget: &SliceBudget,
    job: &mut ForkJobV1,
    source: &RepoId,
) -> Result<(), ForkError> {
    let index = job.cursor as usize;
    let id = job.packs[index].id;
    // The pack is a published, unheld member of the source, in the
    // generation the pair was published in.
    let member = store
        .get(
            &env.shards.membership(source, &BlobKey::pack(id)),
            &keys::published_member(&source.name, &id),
        )
        .await?
        .map(|raw| Witness::decode(&raw))
        .transpose()?;
    if !member.is_some_and(|w| w.visible(false, job.source_generation)) {
        return Err(ForkError::NotFound);
    }
    // A proof that cannot fit a whole slice would strand the fork after it
    // registers the destination: refuse it here, before anything is written.
    let proof = budget.used();
    super::publish::prove(env, store, source, &id, job.source_generation).await?;
    if budget.used().saturating_sub(proof) > super::publish::PROOF_LIMIT {
        return Err(ForkError::TooLarge);
    }
    let facts = inventory::sealed_facts(store, &id)
        .await
        .map_err(|e| match e {
            crate::store::StoreError::Corrupt(_) => ForkError::NotFound,
            other => other.into(),
        })?;
    let mut known: BTreeSet<Hash> = job.pack_ids();
    let mut add = |packs: &[Hash], base: bool, rows: &mut Vec<PackRow>| {
        for pack in packs {
            if known.insert(*pack) {
                rows.push(PackRow {
                    id: *pack,
                    len: 0,
                    objects: 0,
                    node: false,
                    base,
                });
            }
        }
    };
    let mut added = Vec::new();
    let node = facts.packlist.is_some();
    if let Some((prev, listed)) = &facts.packlist {
        if let Some(prev) = prev {
            add(&[*prev], false, &mut added);
        }
        add(listed, false, &mut added);
    } else if facts.dependencies > 0 {
        if facts.dependencies > super::MAX_PACK_DEPS {
            return Err(ForkError::TooLarge);
        }
        let mut wanted = Vec::new();
        inventory::visit_dependencies(store, &id, |dependency, _| {
            wanted.push(dependency);
            std::future::ready(Ok(false))
        })
        .await
        .map_err(|e| match e {
            crate::store::StoreError::Corrupt(_) => ForkError::NotFound,
            other => other.into(),
        })?;
        let mut pending: BTreeSet<Hash> = job.deps.iter().copied().collect();
        for dependency in wanted {
            if pending.insert(dependency) {
                job.deps.push(dependency);
            }
        }
        if job.deps.len() > super::MAX_FORK_DEPS {
            return Err(ForkError::TooLarge);
        }
    }
    let row = &mut job.packs[index];
    row.len = facts.length;
    row.node = node;
    row.objects = facts.count.saturating_sub(facts.dependencies);
    job.packs.extend(added);
    job.cursor += 1;
    Ok(())
}

/// Map up to 256 external-base objects to the source packs that hold them.
async fn resolve<S: NamespaceStore>(
    store: &Budgeted<'_, S>,
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    source: &RepoId,
) -> Result<(), ForkError> {
    let take = job.deps.len().min(index::MAX_LOOKUP_IDS);
    let ids: Vec<Hash> = job.deps[..take].to_vec();
    let found = index::locate_many(store, env.shards, source, &ids).await?;
    let mut known: BTreeSet<Hash> = job.pack_ids();
    for located in found {
        match located {
            Ok(Some(object)) => {
                if known.insert(object.pack) {
                    job.packs.push(PackRow {
                        id: object.pack,
                        len: 0,
                        objects: 0,
                        node: false,
                        base: true,
                    });
                }
            }
            _ => return Err(ForkError::NotFound),
        }
    }
    job.deps.drain(..take);
    Ok(())
}
