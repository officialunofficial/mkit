//! The cleared set: the commits and trees of the inherited closure.
//!
//! The source proved the tip's whole closure when it published it, and the
//! fork copies every pack that closure lives in, so any subset of the closure
//! may be treated as structurally verified. The set holds only commits and
//! trees: skipping a cleared tree skips its whole subtree, so blobs are never
//! listed. A later publication walk skips an object in the set and nothing
//! else; denial and takedown checks are not waived (SPEC-SERVER §9.9).

use super::{ForkEnv, ForkError, ForkJobV1, set, sets};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::store::{Batch, NamespaceStore, index};
use crate::takedown::{denial, inventory};
use mkit_core::hash::Hash;

/// A page of parent rows costs two calls; the reserve leaves room for the seed.
const TREE_RESERVE: u32 = 40;
const WALK_RESERVE: u32 = 150;
/// Objects expanded per walk unit.
const WALK_BATCH: usize = 32;

/// Collect the tree and manifest ids of every data pack, a page of parent
/// rows at a time so a pack with many trees spans slices. Returns the batch
/// fragment holding the set rows, and whether every pack has been read.
pub(crate) async fn trees<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<(Batch, bool), ForkError> {
    let store = Budgeted::new(env.store, budget);
    let dest = job.dest()?;
    let (coordinator, name) = (env.shards.coordinator(&dest.namespace), dest.name);
    let [mut trees, mut manifests] =
        sets::read(&store, &coordinator, &name, [set::TREES, set::MANIFESTS]).await?;
    let fresh = super::fresh(budget);
    let mut progressed = false;
    while (job.cursor as usize) < job.packs.len() {
        if budget.remaining() < TREE_RESERVE {
            break;
        }
        let pack = job.packs[job.cursor as usize];
        if pack.node {
            job.cursor += 1;
            continue;
        }
        let page = inventory::parent_page(&store, &pack.id, job.after.clone()).await;
        let (rows, next) = match page {
            Ok(page) => page,
            Err(e) if crate::budget::is_exhausted(&e) && (progressed || !fresh) => break,
            Err(e) if crate::budget::is_exhausted(&e) => return Err(ForkError::TooLarge),
            Err(crate::store::StoreError::Corrupt(_)) => return Err(ForkError::NotFound),
            Err(e) => return Err(e.into()),
        };
        for (id, row) in rows {
            match row.kind {
                2 => {
                    trees.insert(id);
                }
                5 => {
                    manifests.insert(id);
                }
                _ => {}
            }
        }
        if trees.ids.len() > env.limits.max_set_ids || manifests.ids.len() > env.limits.max_set_ids
        {
            return Err(ForkError::TooLarge);
        }
        if next.is_some() {
            job.after = next;
        } else {
            job.after = None;
            job.cursor += 1;
        }
        progressed = true;
    }
    let mut batch = trees.write(Batch::new(), &name, set::TREES, env.limits.max_set_ids)?;
    batch = manifests.write(batch, &name, set::MANIFESTS, env.limits.max_set_ids)?;
    let done = job.cursor as usize >= job.packs.len();
    if done {
        // Seed the walk and record the inherited external-base packs, which
        // stay dependencies of any skipped object.
        let [mut queue, mut bases] =
            sets::read(&store, &coordinator, &name, [set::QUEUE, set::BASES]).await?;
        queue.insert(job.tip);
        for pack in job.packs.iter().filter(|p| p.base) {
            bases.insert(pack.id);
        }
        batch = queue.write(batch, &name, set::QUEUE, env.limits.max_set_ids)?;
        batch = bases.write(batch, &name, set::BASES, env.limits.max_set_ids)?;
    }
    Ok((batch, done))
}

/// Expand queued commits and trees into the cleared set. Returns the batch
/// fragment and whether the queue is empty.
pub(crate) async fn walk<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    budget: &SliceBudget,
) -> Result<(Batch, bool), ForkError> {
    let source = job.source()?;
    let store = Budgeted::new(env.store, budget);
    let dest = job.dest()?;
    let (coordinator, name) = (env.shards.coordinator(&dest.namespace), dest.name);
    let [trees, mut queue, mut cleared] = sets::read(
        &store,
        &coordinator,
        &name,
        [set::TREES, set::QUEUE, set::CLEARED],
    )
    .await?;
    let fresh = super::fresh(budget);
    let mut progressed = false;
    while !queue.ids.is_empty() && budget.remaining() >= WALK_RESERVE {
        let mut unit = Vec::new();
        while unit.len() < WALK_BATCH
            && let Some(id) = queue.pop()
        {
            unit.push(id);
        }
        let outcome = expand(&store, env, &source, &trees.ids, &unit).await;
        let children = match outcome {
            Ok(children) => children,
            Err(error) if super::spent(&error, budget) => {
                if !progressed && fresh {
                    return Err(ForkError::TooLarge);
                }
                // The unit's reads were discarded: put its ids back.
                for id in unit {
                    queue.insert(id);
                }
                break;
            }
            Err(error) => return Err(error),
        };
        for id in &unit {
            cleared.insert(*id);
        }
        for child in children {
            if !cleared.ids.contains(&child) {
                queue.insert(child);
            }
        }
        if cleared.ids.len() > env.limits.max_set_ids || queue.ids.len() > env.limits.max_set_ids {
            return Err(ForkError::TooLarge);
        }
        progressed = true;
    }
    let done = queue.ids.is_empty();
    let mut batch = queue.write(Batch::new(), &name, set::QUEUE, env.limits.max_set_ids)?;
    batch = cleared.write(batch, &name, set::CLEARED, env.limits.max_set_ids)?;
    Ok((batch, done))
}

/// The commits and trees a unit of cleared objects refers to.
async fn expand<S: NamespaceStore>(
    store: &Budgeted<'_, S>,
    env: &ForkEnv<'_, S>,
    source: &crate::repo::RepoId,
    trees: &std::collections::BTreeSet<Hash>,
    unit: &[Hash],
) -> Result<Vec<Hash>, ForkError> {
    let located = index::locate_many(store, env.shards, source, unit).await?;
    let mut out = Vec::new();
    for (id, located) in unit.iter().zip(located) {
        let Ok(Some(located)) = located else {
            return Err(ForkError::NotFound);
        };
        let row = inventory::entry(store, &located.pack, id)
            .await?
            .ok_or(ForkError::NotFound)?;
        let tree = match row.kind {
            2 => true,
            3 | 4 | 7 => false,
            _ => return Err(ForkError::NotFound),
        };
        if tree && !trees.contains(id) {
            return Err(ForkError::NotFound);
        }
        for n in 0..row.references.pages.len() {
            for child in denial::page(store, &row.references, n).await? {
                // A tree's children matter only when they are trees; a
                // commit's other children are its parents.
                if trees.contains(&child) || !tree {
                    out.push(child);
                }
            }
        }
    }
    Ok(out)
}
