use super::{PushContext, PushError};
use crate::packmap::{flatten_oldest_first, packmap_ref, walk_pack_chain};
use crate::{SourceError, SyncError};
use mkit_core::{
    hash::Hash,
    protocol::{AdvanceOutcome, CommitOutcome, PackKey},
    refs,
    transfer::packmap::{ChainState, PlanError, plan_advance},
};
pub(super) const PACKMAP_CAS_ATTEMPTS: u32 = 8;
/// Walk a branch's packlist chain from `head_key` and return the flat
/// **oldest-first** list of pack keys it references. See
/// [`crate::packmap::walk_pack_chain`] for the walk / integrity-check
/// semantics.
pub(crate) fn resolve_pack_chain(
    tx: &PushContext<'_>,
    branch: &str,
    head_key: Hash,
) -> Result<Vec<Hash>, PushError> {
    // Defined in terms of `probe_chain` so the flattened pack list is
    // identical BY CONSTRUCTION to `probe_chain(..).packs` (the equivalence
    // the `probe_chain_*_matches_resolve_pack_chain` test asserts) — the two
    // can't drift. `probe_chain` can't delegate the other way: it also needs
    // the node count for `depth`.
    Ok(probe_chain(tx, branch, head_key)?.packs)
}

/// A branch's packmap chain, walked exactly once, paired with the packmap
/// value it was walked from.
///
/// Produced by [`probe_chain`] (the push-side pre-plan re-baseline probe in
/// `push_branch`) and consumed by [`advance_packmap`]'s first CAS attempt —
/// so a healthy chain is walked once per push, not twice (mkit #521 perf
/// fix; previously the pre-plan depth probe and `advance_packmap`'s own
/// [`resolve_pack_chain`] call each walked the whole chain independently).
/// `advance_packmap` only reuses this when the packmap's live value still
/// equals `head`; a mismatch (the packmap moved between the probe and the
/// CAS attempt, or a prior CAS attempt already lost the race) falls back to
/// a fresh [`resolve_pack_chain`] call, preserving the existing retry
/// semantics.
#[derive(Debug)]
pub(crate) struct ResolvedChain {
    /// The packmap value this chain was walked from.
    pub(crate) head: Hash,
    /// Chain depth (node count) at `head`.
    pub(crate) depth: usize,
    /// Flattened oldest-first pack keys — identical to what
    /// [`resolve_pack_chain`] would return for `head`.
    pub(crate) packs: Vec<Hash>,
}

/// Walk a branch's packlist chain from `head_key` ONCE, returning both its
/// depth and its flattened oldest-first pack keys as a single
/// [`ResolvedChain`]. Sole caller is `push_branch`'s pre-plan re-baseline
/// probe (#406); see [`ResolvedChain`] for why threading its result into
/// [`advance_packmap`] matters.
pub(crate) fn probe_chain(
    tx: &PushContext<'_>,
    branch: &str,
    head_key: Hash,
) -> Result<ResolvedChain, PushError> {
    let nodes = walk_pack_chain(tx.source, tx.observer, branch, head_key)?;
    let depth = nodes.len();
    let packs = flatten_oldest_first(nodes);
    Ok(ResolvedChain {
        head: head_key,
        depth,
        packs,
    })
}

/// The push-side action, frozen before pack construction and CAS retries.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChainAction {
    /// Validate the prior chain (if any) and append onto it. If the prior
    /// chain is broken, a self-contained pack (`self_contained == true`)
    /// resets to escape it; otherwise the push blocks
    /// ([`SyncError::PackChainInvalid`]).
    Append {
        /// Whether the pack being chained on reconstructs the whole
        /// closure with no external base — the precondition for the
        /// broken-chain escape-hatch reset described above.
        self_contained: bool,
    },
    /// Reset to a full-closure node. Requires atomic advance and a conditioned
    /// head lease. Existing fetchers download the full closure again, and old
    /// pack digests remain in their applied-pack records until pruned.
    ResetSelfContained,
}

/// Advertise new packs in apply order and then move the branch head.
///
/// The shared planner validates idempotency, encodes the node, and supplies its
/// CAS condition. This driver owns chain reads, uploads and eight CAS attempts.
/// A transactional transport commits both refs together; the ordered default
/// commits packmap first, so the head never precedes its reconstructing packs.
///
/// Append validates the entire prior chain. A broken chain permits a reset only
/// for self-contained packs; deltas need its bases and fail with the original
/// error. Transient failures propagate. Proactive resets skip validation and
/// require atomic advance plus a conditioned head lease because a reset is not
/// a superset of the old chain. The caller chooses rollover before pack planning
/// and freezes that choice across retries; concurrent appends can temporarily
/// exceed the depth threshold until the next push resets it.
///
/// `resolved` reuses the pre-plan walk only while its head matches the live ref.
/// A stale probe or lost CAS race requires a fresh walk. An idempotent retry only
/// writes the head. Atomic force pushes use the separate guarded driver,
/// including this idempotent case. Lost-response conflicts are disambiguated
/// by reading the head.
pub(crate) fn advance_packmap(
    tx: &PushContext<'_>,
    branch: &str,
    pack_keys: &[Hash],
    action: ChainAction,
    resolved: Option<ResolvedChain>,
    head_condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), PushError> {
    debug_assert!(
        !pack_keys.is_empty(),
        "advance_packmap requires at least one pack key — callers only reach this with a \
         non-empty plan"
    );
    let packmap_name = packmap_ref(branch);
    let head_name = format!("refs/heads/{branch}");
    // A cached walk is consumed once; retries resolve the live chain again.
    // The caller's append/reset decision stays frozen across attempts.
    let mut cached = resolved;
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err(PushError::Sync(SyncError::Interrupted));
        }
        let prior = tx.read_ref(&packmap_name)?;
        // Decide the new node's `prev`. A re-baseline always resets
        // (skipping prior-chain validation); otherwise validate the WHOLE
        // prior chain before deciding to append vs. reset.
        let state = match action {
            ChainAction::ResetSelfContained => {
                // A reset can discard old closure: both conditioned refs must
                // commit atomically. Keep these guards for direct callers.
                debug_assert!(
                    tx.supports_atomic_advance(),
                    "re-baseline reset requires a transactional advance_refs (mkit #521)"
                );
                debug_assert!(
                    !matches!(head_condition, refs::RefWriteCondition::Any),
                    "re-baseline reset must not run with an `Any` head condition — the \
                     ordered advance_refs fallback would strand the head (mkit #521)"
                );
                ChainState::Reset { prior }
            }
            ChainAction::Append { self_contained } => match prior {
                None => ChainState::Missing,
                Some(p) => {
                    // Reuse only a walk matching the ref read by this attempt.
                    let packs = match cached.take() {
                        Some(c) if c.head == p => Ok(c.packs),
                        _ => resolve_pack_chain(tx, branch, p),
                    };
                    match packs {
                        Ok(packs) => ChainState::Append {
                            head: p,
                            packs: packs.into_iter().collect(),
                        },
                        // Broken chain: a self-contained pack can reset to escape it;
                        // a delta push must block (its bases live in the broken tail).
                        // Transient transport errors propagate (don't reset on a blip).
                        Err(PushError::Sync(SyncError::PackChainInvalid { .. }))
                            if self_contained =>
                        {
                            ChainState::Reset { prior }
                        }
                        Err(e) => return Err(e),
                    }
                }
            },
        };
        let node = plan_advance(state, pack_keys, None).map_err(|error| match error {
            PlanError::Packlist(error) => PushError::from(error),
            PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
        })?;
        let Some(node) = node else {
            return commit_head(tx, &head_name, head_condition, &tip, branch);
        };
        tx.upload_blob_via_ref(&node.bytes, &PackKey::from_hash(node.key), &head_name)
            .map_err(|error| super::repository_operation_error(tx, error))?;
        let commit_keys: Vec<PackKey> = pack_keys
            .iter()
            .copied()
            .map(PackKey::from_hash)
            .chain(std::iter::once(PackKey::from_hash(node.key)))
            .collect();
        // Commit the packmap AND the head together (#408). A transactional
        // transport applies both atomically; the default does packmap-then-
        // head — still safe, the head never lands past an unadvanced packmap.
        match tx
            .advance_refs_committing(
                &head_name,
                head_condition,
                &tip,
                &packmap_name,
                node.condition,
                &node.key,
                &commit_keys,
            )
            .map_err(|error| super::repository_operation_error(tx, error))?
        {
            CommitOutcome::Advanced(AdvanceOutcome::Committed) => return Ok(()),
            // Another pusher advanced the packmap under us — re-read and retry.
            CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict) => {}
            // The head precondition failed. Either the branch moved under
            // us (the push is stale) or the retry ladder re-issued a write
            // that had already landed (SPEC-TRANSPORT §7) — disambiguate.
            CommitOutcome::Advanced(AdvanceOutcome::HeadConflict) => {
                return head_conflict(tx, &head_name, &tip, branch);
            }
            CommitOutcome::TicketRejected => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(PushError::TicketRejected);
            }
            CommitOutcome::PacklistNotInRepository => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(PushError::PacklistNotInRepository);
            }
            CommitOutcome::DeltaBaseUnavailable => return Err(PushError::DeltaBaseUnavailable),
            _ => return Err(PushError::from(SourceError::InvalidResponse)),
        }
    }
    Err(PushError::PackmapContended {
        branch: branch.to_owned(),
    })
}

/// Move just the branch head under its CAS condition, mapping a conflict to
/// the actionable non-fast-forward error. Used when the packmap already
/// advertises the pack (idempotent retry) or a push has nothing to send.
pub(crate) fn commit_head(
    tx: &PushContext<'_>,
    head_name: &str,
    condition: refs::RefWriteCondition,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    match tx.update_ref(head_name, condition, tip) {
        Ok(()) => Ok(()),
        Err(SourceError::RefConflict) => head_conflict(tx, head_name, tip, branch),
        Err(e) => Err(super::repository_operation_error(tx, e)),
    }
}

/// Resolve a failed head precondition (`RefConflict` from `update_ref`,
/// `HeadConflict` from `advance_refs`) per SPEC-TRANSPORT §7: the retry
/// ladder may have re-issued a write whose first attempt landed, so the
/// conflict can be our own write. Re-read the head; if it already holds
/// `tip` the push landed, otherwise it is a genuine non-fast-forward.
///
/// Only the head is checked. Whoever moved the head to `tip` also advanced
/// the packmap to reconstruct it first (packmap-then-head, or both at once),
/// so a head at `tip` already satisfies the push's invariant even if a later
/// pusher has since moved the packmap past our node.
fn head_conflict(
    tx: &PushContext<'_>,
    head_name: &str,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    let current = tx
        .read_ref(head_name)
        .map_err(|error| super::repository_operation_error(tx, error))?;
    if current == Some(*tip) {
        return Ok(());
    }
    Err(PushError::NonFastForwardPush {
        branch: branch.to_owned(),
    })
}
