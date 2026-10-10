//! Publishing the inherited membership, last.

use super::{ForkEnv, ForkError, ForkJobV1, plan};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::repo::RepoId;
use crate::store::publication::Witness;
use crate::store::{
    Batch, BatchOutcome, BlobKey, CONTENT_APPLY_WINDOW_MS, NamespaceStore, Precondition, keys,
};
use crate::takedown::denial;
use mkit_core::hash::Hash;

/// Calls below which a unit is not started. A proof costs about twenty calls
/// plus a few per active takedown descriptor; a unit that runs out anyway ends
/// the slice, keeps what came before it, and is repeated on a whole allowance.
/// Planning refuses a proof too large for [`PROOF_LIMIT`].
const UNIT_RESERVE: u32 = 60;

/// The most calls one proof may cost for the fork to be accepted: a unit adds
/// a source re-read and two row reads and writes to its proof.
pub(super) const PROOF_LIMIT: u32 = super::SLICE_CALLS - 40;

/// The order packs become members: every pack but the packmap head by id,
/// then the head, whose witness carries the boundary flag. A reader that
/// sees the flag therefore sees every other inherited pack.
pub(crate) fn order(job: &ForkJobV1) -> Vec<Hash> {
    let mut ids: Vec<Hash> = job
        .packs
        .iter()
        .map(|p| p.id)
        .filter(|id| *id != job.packmap)
        .collect();
    ids.sort_unstable();
    ids.push(job.packmap);
    ids
}

/// Prove and write each pack, then prove it again, from the cursor. `true`
/// once all are published.
pub(crate) async fn slice<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    let source = job.source()?;
    let dest = job.dest()?;
    let store = Budgeted::new(env.store, budget);
    let order = order(job);
    let fresh = super::fresh(budget);
    let mut progressed = false;
    while (job.cursor as usize) < order.len() {
        if budget.remaining() < UNIT_RESERVE {
            return Ok(false);
        }
        let id = order[job.cursor as usize];
        // Two units per pack, each costing one proof: the write (proof, then
        // the guarded rows) and the check after it. `job.part` says which.
        let unit = match job.part {
            0 => write_one(env, &store, job, &source, &dest, &id).await,
            1 => prove(env, &store, &source, &id, job.source_generation).await,
            _ => return Err(ForkError::Unavailable("fork publish state")),
        };
        match unit {
            Ok(()) => {
                if job.part == 0 {
                    job.part = 1;
                } else {
                    job.part = 0;
                    job.cursor += 1;
                }
                progressed = true;
            }
            // A proof reports a spent allowance as an ordinary failure.
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
    Ok(true)
}

async fn write_one<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &ForkJobV1,
    source: &RepoId,
    dest: &RepoId,
    id: &Hash,
) -> Result<(), ForkError> {
    // The source must still publish this exact pair, immediately before the
    // write: a moved tip fails the fork rather than copy a stale set.
    let view = plan::read_source(store, env.shards, source, &job.source_ref, &job.tip).await?;
    if view.packmap != job.packmap || view.generation != job.source_generation {
        return Err(ForkError::TipChanged);
    }
    prove(env, store, source, id, job.source_generation).await?;
    let witness = Witness {
        generation: super::MEMBERSHIP_GENERATION,
        sequence: 0,
        published: true,
        held: false,
        boundary: *id == job.packmap,
    }
    .encode();
    let target = env.shards.membership(dest, &BlobKey::pack(*id));
    let (live, published) = (
        keys::membership(&dest.name, id),
        keys::published_member(&dest.name, id),
    );
    // The rows are ours to create: an identical pair is a replay, and
    // anything else (a hold a takedown set, a writer's own membership) is
    // never overwritten.
    let rows = store
        .get_many(&target, &[live.clone(), published.clone()])
        .await?;
    match rows.as_slice() {
        [None, None] => {
            let batch = Batch::new()
                // Stamped at the write: the check unit that follows (a proof
                // after the write) is what closes the window between the
                // proof and the write, however long the proof took.
                .require(Precondition::NotAfter(
                    env.now().saturating_add(CONTENT_APPLY_WINDOW_MS),
                ))
                .require(Precondition::Absent(live.clone()))
                .require(Precondition::Absent(published.clone()))
                .put(live, witness.clone())
                .put(published, witness);
            match store.apply(&target, batch).await? {
                BatchOutcome::Committed => {}
                _ => return Err(ForkError::Unavailable("fork publish contended")),
            }
        }
        [Some(a), Some(b)] if *a == witness && *b == witness => {}
        _ => return Err(ForkError::NotEmpty),
    }
    Ok(())
}

/// The pack-level proof both the plan (to refuse before any write) and the
/// publish step (immediately around the write) run.
pub(super) async fn prove<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    source: &RepoId,
    id: &Hash,
    generation: u64,
) -> Result<(), ForkError> {
    let member = store
        .get(
            &env.shards.membership(source, &BlobKey::pack(*id)),
            &keys::published_member(&source.name, id),
        )
        .await?
        .map(|raw| Witness::decode(&raw))
        .transpose()?;
    if !member.is_some_and(|w| w.visible(false, generation)) {
        return Err(ForkError::NotFound);
    }
    let clear = if env.takedown_denial {
        denial::require_pack_clear_sealed(store, env.shards, source, id).await
    } else {
        denial::require_clear(store, id).await
    };
    clear.map_err(|e| {
        if e.public_message() == "object blocked" {
            ForkError::NotFound
        } else {
            ForkError::from(e)
        }
    })
}
