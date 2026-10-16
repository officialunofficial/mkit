//! Publishing the inherited membership, last.

use super::{ForkEnv, ForkError, ForkJobV1};
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

/// `job.part` while the members other than the head are written in waves.
const WRITES: u16 = 2;
/// `job.part` while those members are proved again in waves.
const CHECKS: u16 = 3;

/// Prove and write each pack, then prove it again, from the cursor. `true`
/// once all are published.
///
/// Without pack-level denial the members other than the head are written
/// together, then proved again together, and the head is written and proved
/// last, alone: its flag then still says every other inherited pack is a
/// member. A job in either wave state resumes the same way however wide the
/// next driver can run. With denial a proof can cost most of a slice, and
/// each pack is written and proved in turn.
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
    if job.cursor == 0
        && job.part == 0
        && order.len() > 2
        && !env.takedown_denial
        && super::wave_width(env.store, budget, super::WAVE_UNIT_CALLS) > 1
    {
        job.part = WRITES;
    }
    while (job.cursor as usize) < order.len() {
        if budget.remaining() < UNIT_RESERVE {
            return Ok(false);
        }
        if job.part >= WRITES {
            let (done, failure) = wave(env, &store, budget, job, &source, &dest, &order).await;
            progressed |= done > 0;
            match failure {
                None => {}
                Some(error) if super::spent(&error, budget) => {
                    return if progressed || !fresh {
                        Ok(false)
                    } else {
                        Err(ForkError::TooLarge)
                    };
                }
                Some(error) => return Err(error),
            }
            continue;
        }
        let id = order[job.cursor as usize];
        // Two units per pack, each costing one proof: the write (proof, then
        // the guarded rows) and the check after it. `job.part` says which.
        let unit = match job.part {
            0 => write_one(env, &store, job, &source, &dest, &id).await,
            1 => clear(env, &store, &dest, &id).await,
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

/// One wave of the write or check stage, from the cursor: as many members
/// other than the head as the slice can pay a unit's reserve for. Returns the
/// units that finished, counted from the first, and the failure of the first
/// that did not: replies are read in input order, so a later unit's failure
/// never replaces an earlier one's. The units after a failure may have
/// written their rows; those are repeated by a replay, which finds them.
async fn wave<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    budget: &SliceBudget,
    job: &mut ForkJobV1,
    source: &RepoId,
    dest: &RepoId,
    order: &[Hash],
) -> (usize, Option<ForkError>) {
    let last = order.len() - 1;
    let start = job.cursor as usize;
    let width = super::wave_width(env.store, budget, super::WAVE_UNIT_CALLS);
    let units = &order[start..last.min(start + width)];
    let stage = job.part;
    let replies = {
        let job = &*job;
        futures::future::join_all(units.iter().map(|id| async move {
            if stage == WRITES {
                write_one(env, store, job, source, dest, id).await
            } else {
                clear(env, store, dest, id).await
            }
        }))
        .await
    };
    let mut done = 0;
    let mut failure = None;
    for reply in replies {
        match reply {
            Ok(()) => done += 1,
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    job.cursor += u32::try_from(done).unwrap_or(0);
    if job.cursor as usize >= last {
        // Every member but the head has been through this stage.
        if stage == WRITES {
            (job.part, job.cursor) = (CHECKS, 0);
        } else {
            (job.part, job.cursor) = (0, u32::try_from(last).unwrap_or(0));
        }
    }
    (done, failure)
}

async fn write_one<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &ForkJobV1,
    _source: &RepoId,
    dest: &RepoId,
    id: &Hash,
) -> Result<(), ForkError> {
    // Installation projects an immutable accepted binding. Source changes
    // after its final proof are ordered after acceptance, so only the live
    // destination denial/lifecycle proof is repeated here.
    if job.accepted.as_ref() != Some(&super::accept::result(job)?) {
        return Err(ForkError::Unavailable("fork acceptance missing"));
    }
    clear(env, store, dest, id).await?;
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
    let pair = [live.clone(), published.clone()];
    let rows = store.get_many(&target, &pair).await?;
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
                .put(published, witness.clone());
            match store.apply(&target, batch).await? {
                BatchOutcome::Committed => {}
                BatchOutcome::PreconditionFailed { .. } => {
                    // Another driver may have published this exact unit.
                    // Accept only its complete, byte-identical witness pair.
                    let rows = store.get_many(&target, &pair).await?;
                    match rows.as_slice() {
                        [Some(a), Some(b)] if *a == witness && *b == witness => {}
                        _ if rows.iter().flatten().any(|row| *row != witness) => {
                            return Err(ForkError::NotEmpty);
                        }
                        _ => return Err(ForkError::Unavailable("fork publish raced")),
                    }
                }
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(ForkError::Unavailable("fork publish deadline"));
                }
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
    clear(env, store, source, id).await
}

/// Current denial and lifecycle proof for an accepted destination pack.
async fn clear<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    repo: &RepoId,
    id: &Hash,
) -> Result<(), ForkError> {
    let clear = if env.takedown_denial {
        denial::require_pack_clear_sealed(store, env.shards, repo, id).await
    } else {
        denial::require_clear(
            &crate::store::DenialReads::new(store, env.takedown_denial),
            id,
        )
        .await
    };
    clear.map_err(|e| {
        if e.public_message() == "object blocked" {
            ForkError::NotFound
        } else {
            ForkError::from(e)
        }
    })
}
