//! Fetching: reconstruct every remote branch from its packmap chain and
//! publish remote-tracking refs.
//!
//! Each branch is fetched in two phases (#642): the packs are fully
//! downloaded to private staging before the repo lock is taken, and the lock
//! is held only from the first local write through the branch's ref publish.
//! That is narrow enough that a slow transfer does not serialize out
//! unrelated commands, while still closing the GC-prune race: a concurrent
//! `gc` needs the same lock, so it can never observe a downloaded but
//! unpublished object.

use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};

use crate::applied_packs::AppliedPacks;
use std::path::Path;

use crate::SyncOptions;
use crate::error::SyncError;
use crate::lock::acquire_worktree_lock;
use crate::observer::{SyncEvent, SyncObserver};
use crate::packmap::{packmap_ref, resolve_pack_chain};
use crate::source::RemoteSource;
use crate::stage::{StagedPacks, download_pack_chain, unpack_downloaded_packs};

/// What a fetch did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchReport {
    /// Branches whose remote-tracking ref was published.
    pub branches_fetched: usize,
    /// Branches skipped because the listing was stale (deleted since).
    pub branches_skipped: Vec<String>,
    /// Packs downloaded and applied.
    pub packs_downloaded: usize,
    /// Packs already recorded as applied, so neither downloaded nor unpacked.
    pub packs_already_applied: usize,
    /// Objects written to the object store.
    pub objects_unpacked: usize,
}

/// One branch's pack chain, resolved and downloaded over the network with
/// **no repo lock held**. Consumed by [`apply_fetched_chain`], which the
/// caller must run under the repo lock.
pub(crate) struct FetchedChain {
    /// Oldest-first flattened chain. Retained (not just `downloaded`) so a
    /// self-heal retry inside [`apply_fetched_chain`] can re-download without
    /// re-walking the packlist chain.
    chain: Vec<Hash>,
    /// Private, verified files for missing packs in apply order. Payload
    /// bytes are never retained across download iterations.
    downloaded: StagedPacks,
}

/// Phase 1 of a branch fetch: walk `branch`'s packmap chain from `head_key`
/// and download every pack in it not already recorded in `applied`. Pure
/// network I/O (the local object store is never touched), so the caller does
/// not need the repo lock.
///
/// Packs already recorded in `applied` are skipped, so a steady-state fetch
/// only pays for packs new since the last fetch. The chain itself is still
/// resolved in full every time: node downloads are small blobs and remain the
/// source of truth for chain shape.
pub(crate) fn resolve_and_download_chain(
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    branch: &str,
    head_key: Hash,
    applied: &AppliedPacks,
    stage_parent: Option<&Path>,
) -> Result<FetchedChain, SyncError> {
    let chain = resolve_pack_chain(source, observer, branch, head_key)?;
    let downloaded = download_pack_chain(source, observer, branch, &chain, applied, stage_parent)?;
    Ok(FetchedChain { chain, downloaded })
}

/// What [`apply_fetched_chain`] did, for the report.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Applied {
    pub(crate) packs_downloaded: usize,
    pub(crate) packs_skipped: usize,
    pub(crate) objects_unpacked: usize,
}

/// Phase 2 of a branch fetch: unpack `fetched`'s downloaded packs into
/// `store` and verify the closure at `tip` is complete, running the
/// applied-pack self-heal retry on a stale-record failure.
///
/// **The caller MUST hold the repo lock across this call, through the
/// branch's subsequent ref publish.** Unpacking writes objects to the local
/// store before this branch's ref makes them reachable; a concurrent `gc`
/// must not be able to observe that store state.
///
/// # Self-heal
///
/// Exactly one failure mode is treated as local staleness: the closure check
/// reporting [`SyncError::RemoteMissingObject`] on a run that skipped at least
/// one recorded pack. The record claimed packs were applied but their objects
/// are not in the store (for example `.mkit/objects` was wiped while
/// `applied-packs/` survived), so `applied` is cleared in memory and the
/// whole chain is retried once with no skips. Every other failure propagates
/// without triggering self-heal, because none is evidence the local store is
/// stale: a corrupt pack, a remote missing a pack, a transport error, a
/// closure too large to verify, an interruption, or a failed signature.
///
/// # Signature verification
///
/// When `require_signed` is `true` every commit, remix and tag in each
/// freshly unpacked pack is verified before the pack is recorded as applied.
/// On the self-heal path every re-downloaded object is re-verified.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_fetched_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    remote: &str,
    branch: &str,
    fetched: FetchedChain,
    tip: Hash,
    applied: &mut AppliedPacks,
    require_signed: bool,
    stage_parent: Option<&Path>,
) -> Result<Applied, SyncError> {
    let FetchedChain { chain, downloaded } = fetched;
    let mut stats = Applied {
        packs_downloaded: downloaded.packs.len(),
        packs_skipped: chain.len() - downloaded.packs.len(),
        objects_unpacked: 0,
    };
    stats.objects_unpacked +=
        unpack_downloaded_packs(store, observer, downloaded, applied, require_signed)?;

    // Closure completeness. With skips this is the sole guarantee the store
    // is whole, and a `RemoteMissingObject` here is the ONLY self-heal
    // trigger.
    match verify_closure_present(store, &tip) {
        Ok(()) => Ok(stats),
        Err(e @ SyncError::RemoteMissingObject(_)) if stats.packs_skipped > 0 => {
            observer.event(&SyncEvent::AppliedPacksStale {
                remote: remote.to_owned(),
                branch: branch.to_owned(),
                cause: e.to_string(),
            });
            // Clear the suspected-stale record in memory and retry the whole
            // chain with no skips. Clearing intentionally discards digests
            // inserted by other branches earlier in this same fetch: the
            // store wipe that trips self-heal makes those entries just as
            // stale.
            applied.clear();
            let downloaded =
                download_pack_chain(source, observer, branch, &chain, applied, stage_parent)?;
            stats.packs_downloaded = downloaded.packs.len();
            stats.packs_skipped = 0;
            stats.objects_unpacked +=
                unpack_downloaded_packs(store, observer, downloaded, applied, require_signed)?;
            verify_closure_present(store, &tip)?;
            Ok(stats)
        }
        Err(e) => Err(e),
    }
}

/// Assert that every object reachable from `tip` is already present in the
/// local store after the packmap chain has been unpacked. A pure integrity
/// check with no network access: a reachable object the chain failed to
/// deliver surfaces as [`SyncError::RemoteMissingObject`], so the fetch aborts
/// loudly rather than publishing a ref to a closure it cannot reconstruct.
///
/// A closure exceeding the [`mkit_core::ops::graph::MAX_REACHABLE`] cap leaves
/// objects past the cap unchecked, which over a partially wiped store could
/// hide missing objects, so truncation is a hard
/// [`SyncError::ClosureTooLarge`] (deliberately not a self-heal trigger).
pub(crate) fn verify_closure_present(store: &ObjectStore, tip: &Hash) -> Result<(), SyncError> {
    match mkit_core::ops::reachable_closure_checked(store, std::iter::once(tip)) {
        Ok((_, false)) => Ok(()),
        Ok((_, true)) => Err(SyncError::ClosureTooLarge(
            mkit_core::ops::graph::MAX_REACHABLE,
        )),
        Err(StoreError::ObjectNotFound(hex)) => Err(SyncError::RemoteMissingObject(hex)),
        Err(e) => Err(e.into()),
    }
}

/// Reconstruct every remote `refs/heads/*` from its packmap chain and publish
/// the remote-tracking refs. `target_branch` (a `clone -b` or `pull` target)
/// is fetched even when an eventual listing has not caught up with it: the
/// branch is strongly read by name, fetched if present, and
/// [`SyncError::RemoteBranchMissing`] if absent.
///
/// For every advertised branch the flow is exactly:
///
/// 1. read the branch's packmap ref (`refs/mkit/packmap/<branch>`),
/// 2. walk its chain oldest-first and download any pack the applied-pack
///    record does not already have, with no repo lock held,
/// 3. acquire the repo lock, unpack the downloaded packs and assert the tip's
///    closure is fully present, then publish the remote-tracking ref and
///    release the lock.
///
/// Steps 3's unpack and closure check are one call so a closure failure
/// counts toward the applied-pack self-heal retry. An absent packmap beside a
/// present head is [`SyncError::PackmapMissing`]; a head absent too is a stale
/// listing, and the branch is skipped. A tracking ref is never published for
/// a closure that could not be fully materialised.
///
/// # Concurrent re-baseline
///
/// Branch tips are listed BEFORE each branch's packmap is read, so a
/// concurrent push that resets the packmap in between can leave an old tip
/// verified against a packmap that only covers the new one, surfacing as
/// [`SyncError::RemoteMissingObject`]. That is transient, so on that error
/// the branch's current tip and packmap are re-read and the chain retried
/// once. A second failure, or a vanished branch, propagates.
///
/// # Applied-packs record
///
/// The record is keyed by remote, so this function owns its lifecycle for the
/// whole fetch: loaded once before the branch loop, persisted once after,
/// unconditionally and best-effort (a pure performance cache whose own I/O
/// must never fail a fetch whose objects durably landed).
pub(crate) fn fetch_objects(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    remote: &str,
    options: &SyncOptions,
) -> Result<FetchReport, SyncError> {
    let mut applied = AppliedPacks::load_or_empty(layout, remote, observer);
    let mut report = FetchReport::default();
    let result = fetch_objects_inner(
        store,
        layout,
        source,
        observer,
        remote,
        options,
        &mut applied,
        &mut report,
    );
    if let Err(e) = applied.persist() {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
    }
    result.map(|()| report)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fetch_objects_inner(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    remote: &str,
    options: &SyncOptions,
    applied: &mut AppliedPacks,
    report: &mut FetchReport,
) -> Result<(), SyncError> {
    let target_branch = options.target_branch.as_deref();
    let require_signed = options.verify_signatures;
    let stage_parent = options.staging_dir.as_deref();
    let mut remote_refs = source
        .list_branches()
        .map_err(|error| source.repository_error(error))?;
    if let Some(branch) = target_branch
        && !remote_refs.iter().any(|r| r.name == branch)
    {
        // The listing may be stale (eventual): a strong read by name decides
        // whether the branch exists. A transport error here propagates; only
        // `Ok(None)` is the "no such branch" verdict.
        match source.read_ref(&format!("refs/heads/{branch}"))? {
            Some(hash) => remote_refs.push(refs::Ref {
                name: branch.to_owned(),
                hash: Some(hash),
            }),
            None => return Err(SyncError::RemoteBranchMissing(branch.to_owned())),
        }
    }
    // Batch every fetched branch's remote-tracking-ref write: `tracking.write`
    // still runs inside this branch's lock scope below, so ref visibility
    // timing is unchanged from per-branch publish-then-unlock; only the
    // parent-directory fsync is deferred to one pass after the loop.
    let mut tracking = refs::RemoteRefBatch::new(layout, remote)?;
    let result: Result<(), SyncError> = (|| {
        for r in remote_refs {
            if observer.cancelled() {
                return Err(SyncError::Interrupted);
            }
            let Some(h) = r.hash else { continue };
            // A branch tip without a packmap is a corrupt or incomplete
            // remote, not a format to degrade to: the push path ALWAYS
            // advertises a packmap before moving the branch ref. A real
            // transport error propagates unchanged; only `Ok(None)` is the
            // explicit "no packmap" verdict.
            //
            // The one exception is a stale listing: a branch deleted since
            // the listing can still be named. Re-read the head strongly:
            // absent too means the listing is stale, so skip the branch and
            // write no tracking ref; present means corruption, which stays
            // `PackmapMissing`.
            let Some(chain_head) = source.read_ref(&packmap_ref(&r.name))? else {
                if source
                    .read_ref(&format!("refs/heads/{}", r.name))?
                    .is_none()
                {
                    observer.event(&SyncEvent::BranchSkippedStale {
                        branch: r.name.clone(),
                    });
                    report.branches_skipped.push(r.name.clone());
                    continue;
                }
                return Err(SyncError::PackmapMissing(r.name.clone()));
            };

            // Phase 1: resolve this branch's chain and download its packs.
            // No repo lock is held.
            let fetched = resolve_and_download_chain(
                source,
                observer,
                &r.name,
                chain_head,
                applied,
                stage_parent,
            )?;

            // Phase 2: unpack, verify and publish this branch's ref under a
            // repo lock acquired fresh for this branch and released once this
            // loop iteration ends, never held across another branch's
            // download.
            let lock = acquire_worktree_lock(layout, observer)?;
            // The tip we publish: normally the listed `h`, but if the chain
            // fails because a concurrent re-baseline moved the branch under
            // us, the freshly re-read tip. The match also carries the lock
            // guard out, so whichever branch runs, the correct (possibly
            // re-acquired) guard is held at `tracking.write` below.
            let (published_tip, _lock, applied_stats) = match apply_fetched_chain(
                store,
                source,
                observer,
                remote,
                &r.name,
                fetched,
                h,
                applied,
                require_signed,
                stage_parent,
            ) {
                Ok(stats) => (h, lock, stats),
                Err(e @ SyncError::RemoteMissingObject(_)) => {
                    // Re-read the branch's CURRENT tip and packmap. If either
                    // is gone (branch deleted mid-fetch) the original error
                    // stands. Otherwise retry the chain ONCE with the fresh
                    // pair; a second failure propagates via `?`.
                    let (Some(fresh_h), Some(fresh_head)) = (
                        source.read_ref(&format!("refs/heads/{}", r.name))?,
                        source.read_ref(&packmap_ref(&r.name))?,
                    ) else {
                        return Err(e);
                    };
                    // Release the lock for the retry's network re-download
                    // too, mirroring phase 1's unlocked download, and
                    // re-acquire before the retry's local unpack and publish,
                    // which still need the GC-prune protection.
                    drop(lock);
                    let fresh_fetched = resolve_and_download_chain(
                        source,
                        observer,
                        &r.name,
                        fresh_head,
                        applied,
                        stage_parent,
                    )?;
                    let lock = acquire_worktree_lock(layout, observer)?;
                    let stats = apply_fetched_chain(
                        store,
                        source,
                        observer,
                        remote,
                        &r.name,
                        fresh_fetched,
                        fresh_h,
                        applied,
                        require_signed,
                        stage_parent,
                    )?;
                    (fresh_h, lock, stats)
                }
                Err(e) => return Err(e),
            };
            // Still inside the lock's scope.
            tracking.write(&r.name, &published_tip)?;
            report.branches_fetched += 1;
            report.packs_downloaded += applied_stats.packs_downloaded;
            report.packs_already_applied += applied_stats.packs_skipped;
            report.objects_unpacked += applied_stats.objects_unpacked;
        }
        Ok(())
    })();
    // Commit whatever tracking-ref writes succeeded regardless of how the
    // loop above ended: a mid-loop failure still durably publishes the prefix
    // that already verified successfully.
    tracking.commit()?;
    result
}
