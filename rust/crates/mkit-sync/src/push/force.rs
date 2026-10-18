//! Force publication keeps the planning dependencies in the atomic ref write.
use super::{
    PackSink, PreparedPlan, PushContext, PushError, RetryReason, build_and_upload_packs,
    effective_payload_cap, encode_delta_candidates_batch, estimate_pack_sizes,
    estimated_ticketed_count, packmap::PACKMAP_CAS_ATTEMPTS, repository_operation_error, split,
};
use crate::SyncError;
use crate::packmap::{flatten_oldest_first, packmap_ref, walk_pack_chain};
use mkit_core::{
    hash::Hash,
    protocol::{AdvanceOutcome, CommitOutcome, PackKey, UploadLimits},
    refs::RefWriteCondition,
    store::ObjectStore,
    transfer::{
        self,
        packmap::{ChainState, PlanError, plan_advance},
    },
};

#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    pub packmap: Option<Hash>,
    pub head: Option<Hash>,
}

pub(super) fn checked_upload_limits(
    tx: &PushContext<'_>,
    condition: RefWriteCondition,
) -> Result<UploadLimits, PushError> {
    let limits = tx.upload_limits();
    if matches!(condition, RefWriteCondition::Any) && tx.atomic_advance_status().is_none() {
        return Err(PushError::ForceCapabilityUnknown);
    }
    Ok(limits)
}

pub(super) fn snapshot(
    tx: &PushContext<'_>,
    branch: &str,
    head: Option<Hash>,
    condition: RefWriteCondition,
) -> Result<Option<Snapshot>, PushError> {
    if matches!(condition, RefWriteCondition::Any) && tx.supports_atomic_advance() {
        Ok(Some(Snapshot {
            packmap: tx.read_ref(&packmap_ref(branch))?,
            head,
        }))
    } else {
        Ok(None)
    }
}

struct Uploaded {
    snapshot: Snapshot,
    keys: Vec<Hash>,
    dependent: bool,
    cached: Option<(Option<Hash>, ChainState)>,
    read_current: bool,
}

struct Publication {
    prior: Option<Hash>,
    node: Hash,
    keys: Vec<PackKey>,
}

struct ForcePush<'a, 'source> {
    tx: &'a PushContext<'source>,
    store: &'a ObjectStore,
    branch: &'a str,
    head_name: String,
    packmap_name: String,
    tip: Hash,
    probe: bool,
    cap: u64,
    limits: UploadLimits,
}

/// Every publication attempt and every re-plan spends the same CAS budget.
/// Upload-rejection recovery remains restart-once within that budget.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_step(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    mut preplanned: Option<PreparedPlan>,
) -> Result<(), PushError> {
    let limits = tx.upload_limits();
    let push = ForcePush {
        tx,
        store,
        branch,
        tip,
        limits,
        head_name: format!("refs/heads/{branch}"),
        packmap_name: packmap_ref(branch),
        probe: rebaseline_threshold > 0,
        cap: effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?,
    };
    let mut uploaded: Option<Uploaded> = None;
    let mut recovery = None;
    let mut recovered_upload = false;
    let mut replanned = false;
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err(SyncError::Interrupted.into());
        }
        if uploaded.is_none() {
            uploaded = push.prepare(preplanned.take(), recovery, replanned)?;
            if uploaded.is_none() {
                replanned = true;
                continue;
            }
        }
        let staged = uploaded.as_mut().expect("prepared above");
        let Some(publication) = push.publication(staged)? else {
            uploaded = None;
            replanned = true;
            continue;
        };
        let head_condition = if staged.dependent {
            staged
                .snapshot
                .head
                .map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
        } else {
            tx.atomic_force_head_condition(staged.snapshot.head)
        };
        let outcome = tx
            .advance_refs_committing(
                &push.head_name,
                head_condition,
                &tip,
                &push.packmap_name,
                publication
                    .prior
                    .map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
                &publication.node,
                &publication.keys,
            )
            .map_err(|error| repository_operation_error(tx, error))?;
        match outcome {
            CommitOutcome::Advanced(AdvanceOutcome::Committed) => return Ok(()),
            CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict) => {
                let current = tx.read_ref(&push.packmap_name)?;
                if chain_state(
                    tx,
                    branch,
                    current,
                    staged.snapshot.packmap,
                    !staged.dependent,
                )?
                .is_none()
                {
                    uploaded = None;
                    replanned = true;
                }
            }
            CommitOutcome::Advanced(AdvanceOutcome::HeadConflict) => {
                if tx.read_ref(&push.head_name)? == Some(tip) {
                    return Ok(());
                }
                uploaded = None;
                replanned = true;
            }
            CommitOutcome::TicketRejected
            | CommitOutcome::PacklistNotInRepository
            | CommitOutcome::DeltaBaseUnavailable => {
                if outcome != CommitOutcome::DeltaBaseUnavailable
                    && tx.read_ref(&push.head_name)? == Some(tip)
                {
                    return Ok(());
                }
                recovery = Some(ForcePush::recover_upload(outcome, &mut recovered_upload)?);
                uploaded = None;
            }
            _ => return Err(crate::SourceError::InvalidResponse.into()),
        }
    }
    Err(PushError::PackmapContended {
        branch: branch.to_owned(),
    })
}

impl ForcePush<'_, '_> {
    fn recover_upload(outcome: CommitOutcome, used: &mut bool) -> Result<RetryReason, PushError> {
        if *used {
            return Err(match outcome {
                CommitOutcome::TicketRejected => PushError::TicketRejected,
                CommitOutcome::PacklistNotInRepository => PushError::PacklistNotInRepository,
                _ => PushError::DeltaBaseUnavailable,
            });
        }
        *used = true;
        Ok(if outcome == CommitOutcome::DeltaBaseUnavailable {
            RetryReason::LostDeltaBase
        } else {
            RetryReason::Replanned
        })
    }

    fn prepare(
        &self,
        preplanned: Option<PreparedPlan>,
        recovery: Option<RetryReason>,
        replanned: bool,
    ) -> Result<Option<Uploaded>, PushError> {
        let (snapshot, plan) = if let Some(prepared) = preplanned {
            (
                prepared.force.expect("force pre-plan has its snapshot"),
                prepared.pack,
            )
        } else {
            // These strong reads need not form an atomic snapshot. A dependent
            // plan compares both values, including an identical-root reset.
            let packmap = self.tx.read_ref(&self.packmap_name)?;
            let head = self.tx.read_ref(&self.head_name)?;
            let plan = transfer::plan_pack_with(
                self.store,
                self.tip,
                if recovery == Some(RetryReason::LostDeltaBase) {
                    None
                } else {
                    head
                },
                encode_delta_candidates_batch,
            )?;
            (Snapshot { packmap, head }, plan)
        };
        let empty = plan.is_empty();
        let dependent = empty || !plan.self_contained;
        // Keep the ordinary force append policy and reuse its chain probe.
        let cached = if !empty && self.probe {
            let prior = self.tx.read_ref(&self.packmap_name)?;
            let Some(state) =
                chain_state(self.tx, self.branch, prior, snapshot.packmap, !dependent)?
            else {
                return Ok(None);
            };
            Some((prior, state))
        } else {
            None
        };
        if let Some(reason) = recovery.or(replanned.then_some(RetryReason::PackmapChanged))
            && estimated_ticketed_count(
                &estimate_pack_sizes(self.store, &plan, self.cap, self.limits.max_pack_bytes)?,
                self.limits,
            ) > split::data_pack_budget(self.limits)
            && let Err(PushError::PushTooLarge { packs, limit, .. }) = build_and_upload_packs(
                PackSink::Count,
                self.store,
                plan.clone(),
                self.cap,
                self.limits,
                self.tx.observer,
            )
        {
            return Err(PushError::RetryTooLarge {
                reason,
                packs,
                limit,
            });
        }
        let keys = if empty {
            Vec::new()
        } else {
            build_and_upload_packs(
                PackSink::Upload {
                    tx: self.tx,
                    head_ref: &self.head_name,
                },
                self.store,
                plan,
                self.cap,
                self.limits,
                self.tx.observer,
            )?
        };
        Ok(Some(Uploaded {
            snapshot,
            keys,
            dependent,
            cached,
            read_current: !empty,
        }))
    }

    fn publication(&self, staged: &mut Uploaded) -> Result<Option<Publication>, PushError> {
        let prior = if staged.read_current {
            self.tx.read_ref(&self.packmap_name)?
        } else {
            staged.snapshot.packmap
        };
        staged.read_current = true;
        let mut keys: Vec<PackKey> = staged
            .keys
            .iter()
            .copied()
            .map(PackKey::from_hash)
            .collect();
        let node = if staged.keys.is_empty() {
            // A missing earlier packmap may have raced branch creation.
            let Some(prior) = prior else {
                return Ok(None);
            };
            if Some(prior) != staged.snapshot.packmap
                && chain_state(
                    self.tx,
                    self.branch,
                    Some(prior),
                    staged.snapshot.packmap,
                    false,
                )?
                .is_none()
            {
                return Ok(None);
            }
            prior
        } else {
            let state = match staged.cached.take() {
                Some((head, state)) if head == prior => Some(state),
                _ => chain_state(
                    self.tx,
                    self.branch,
                    prior,
                    staged.snapshot.packmap,
                    !staged.dependent,
                )?,
            };
            let Some(state) = state else {
                return Ok(None);
            };
            let node = plan_advance(state, &staged.keys, None).map_err(|error| match error {
                PlanError::Packlist(error) => PushError::from(error),
                PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
            })?;
            if let Some(node) = node {
                self.tx
                    .upload_blob_via_ref(
                        &node.bytes,
                        &PackKey::from_hash(node.key),
                        &self.head_name,
                    )
                    .map_err(|error| repository_operation_error(self.tx, error))?;
                keys.push(PackKey::from_hash(node.key));
                node.key
            } else {
                // Idempotency compares the packmap in the same atomic write;
                // a plain head write has the same concurrent-reset race.
                keys.clear();
                prior.expect("an advertised pack has a packmap")
            }
        };
        Ok(Some(Publication { prior, node, keys }))
    }
}

/// A valid replacement must retain the immutable node the plan captured.
/// An intact but unrelated chain is insufficient for a dependent pack.
fn chain_state(
    tx: &PushContext<'_>,
    branch: &str,
    prior: Option<Hash>,
    anchor: Option<Hash>,
    self_contained: bool,
) -> Result<Option<ChainState>, PushError> {
    let Some(head) = prior else {
        return Ok(if anchor.is_none() {
            Some(ChainState::Missing)
        } else {
            None
        });
    };
    let nodes = match walk_pack_chain(tx.source, tx.observer, branch, head) {
        Ok(nodes) => nodes,
        Err(SyncError::PackChainInvalid { .. }) if self_contained => {
            return Ok(Some(ChainState::Reset { prior }));
        }
        Err(error) => return Err(error.into()),
    };
    if anchor.is_some_and(|key| key != head && !nodes.iter().any(|node| node.prev == Some(key))) {
        return Ok(None);
    }
    Ok(Some(ChainState::Append {
        head,
        packs: flatten_oldest_first(nodes).into_iter().collect(),
    }))
}
