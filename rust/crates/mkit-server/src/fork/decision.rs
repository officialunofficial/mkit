//! Lower retained fork state into pure progress and clearance decisions.
//!
//! Logical commitments below are request-local observation tokens. They introduce
//! no protocol hash domain or stored encoding. Storage CAS still compares the
//! original complete rows; a hash comparison never replaces a storage guard.

use mkit_core::hash::{Hash, hash};
use mkit_primitives::{
    decision::RefName,
    evidence::{RepositoryId, Revision},
    fork::{
        ForkAdvanceDecision, ForkAdvanceFacts, ForkAdvancePhase, ForkAdvanceRefusal,
        ForkEpochFence, ForkObservation, ForkProgress, ForkReservationFence,
        ForkResult as SemanticResult, decide_fork_advance, decide_fork_authority,
    },
};

use super::{FenceRowsV1, ForkError, ForkJobV1, ForkResult, Phase};
use crate::store::Value;

fn observation(row: Option<&[u8]>) -> ForkObservation {
    row.map_or(ForkObservation::Absent, |bytes| {
        ForkObservation::Present(Revision(hash(bytes)))
    })
}

pub(super) fn authority(
    recorded: &FenceRowsV1,
    job: &ForkJobV1,
    rows: &[Option<Value>],
) -> Result<(), ForkError> {
    if rows.len() != 2 {
        return Err(ForkError::Unavailable("fork fence read"));
    }
    let epoch = job
        .fence
        .as_ref()
        .is_some_and(|f| f.grant_epoch.is_some())
        .then(|| {
            ForkEpochFence::new(
                observation(recorded.epoch.as_deref()),
                observation(rows.get(1).and_then(Option::as_ref).map(Value::as_bytes)),
            )
        });
    match decide_fork_authority(
        observation(recorded.authority.as_deref()),
        observation(rows.first().and_then(Option::as_ref).map(Value::as_bytes)),
        epoch.as_ref(),
    ) {
        Some(reason) => Err(refusal(reason)),
        None => Ok(()),
    }
}

pub(super) fn refusal(reason: ForkAdvanceRefusal) -> ForkError {
    match reason {
        ForkAdvanceRefusal::AuthorityMoved => ForkError::Moved("authority"),
        ForkAdvanceRefusal::EpochMoved => ForkError::Moved("epoch"),
        ForkAdvanceRefusal::Expired | ForkAdvanceRefusal::ReservationSettled => ForkError::Expired,
        // A refusal this server does not know never advances: it is retryable
        // until the server is updated to classify it.
        _ => ForkError::Unavailable("fork advance refusal"),
    }
}

pub(super) fn facts(
    job: &ForkJobV1,
    raw: &Value,
    rows: &[Option<Value>],
    reservation: Option<&Value>,
) -> Result<ForkAdvanceFacts, ForkError> {
    let dest = job.dest()?;
    let destination = crate::store::repo_storage::identity(&dest.namespace, &dest.name);
    Ok({
        let mut v = ForkAdvanceFacts::new(
            job.binding,
            RepositoryId(hash(destination.as_bytes())),
            ForkProgress::new(
                match job.phase {
                    Phase::Done => ForkAdvancePhase::Complete,
                    Phase::Failed => ForkAdvancePhase::Failed,
                    _ if job.accepted.is_some() => ForkAdvancePhase::Accepted,
                    _ => ForkAdvancePhase::Preparing,
                },
                u64::from(job.cursor),
                job.part,
                Revision(hash(raw.as_bytes())),
            ),
            job.expires_ms,
        );
        v.recorded_authority = observation(job.fence_rows.authority.as_deref());
        v.authority = observation(rows.first().and_then(Option::as_ref).map(Value::as_bytes));
        v.grant_epoch = job
            .fence
            .as_ref()
            .is_some_and(|f| f.grant_epoch.is_some())
            .then(|| {
                ForkEpochFence::new(
                    observation(job.fence_rows.epoch.as_deref()),
                    observation(rows.get(1).and_then(Option::as_ref).map(Value::as_bytes)),
                )
            });
        v.reservation = job
            .settle
            .as_ref()
            .filter(|s| job.accepted.is_none() && !s.rid.is_empty())
            .map(|s| {
                ForkReservationFence::new(
                    mkit_primitives::decision::ReservationId(hash(s.rid.as_bytes())),
                    Revision(hash(&s.pending)),
                    observation(reservation.map(Value::as_bytes)),
                )
            });
        v
    })
}

pub(super) fn progress(facts: &ForkAdvanceFacts, now: u64) -> Result<(), ForkError> {
    match *decide_fork_advance(facts, now).decision() {
        ForkAdvanceDecision::Advance => Ok(()),
        ForkAdvanceDecision::Refuse(reason) => Err(refusal(reason)),
        ForkAdvanceDecision::Terminal => Err(ForkError::Unavailable("fork terminal progress")),
        _ => Err(ForkError::Unavailable("fork advance decision")),
    }
}

pub(super) fn generation(value: u64) -> Revision {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Revision(bytes)
}

pub(super) fn result(result: &ForkResult) -> SemanticResult {
    SemanticResult::new(
        RefName(result.source_ref.clone()),
        RepositoryId(hash(result.source.as_bytes())),
        result.source_sequence,
        result.tip,
        result.packmap,
        result.pack_count,
        result.pack_bytes,
        result.object_count,
        result.pack_set,
        generation(result.membership_generation),
    )
}

pub(super) fn inventory(job: &ForkJobV1) -> Result<Vec<Hash>, ForkError> {
    if job.packs.len() > super::MAX_FORK_PACKS {
        return Err(ForkError::TooLarge);
    }
    let mut packs = Vec::new();
    packs
        .try_reserve_exact(job.packs.len())
        .map_err(|_| ForkError::TooLarge)?;
    packs.extend(job.packs.iter().map(|p| p.id));
    packs.sort_unstable();
    if packs.windows(2).any(|w| w[0] == w[1]) {
        return Err(ForkError::Unavailable("fork inventory corrupt"));
    }
    Ok(packs)
}

/// Immutable acceptance projection shared by one physical unit's read and retry.
pub(super) struct Activation {
    expected: SemanticResult,
    accepted: SemanticResult,
    packs: Vec<Hash>,
}

fn limits() -> mkit_primitives::fork::ForkActivationLimits {
    mkit_primitives::fork::ForkActivationLimits::new(
        super::MAX_FORK_PACKS as u64,
        crate::refs::MAX_REF_NAME_BYTES as u64,
        40_000,
    )
}

impl Activation {
    pub(super) fn new(job: &ForkJobV1) -> Result<Self, ForkError> {
        if job.packs.len() > super::MAX_FORK_PACKS
            || job.source_ref.len() > crate::refs::MAX_REF_NAME_BYTES
            || job
                .accepted
                .as_ref()
                .is_some_and(|r| r.source_ref.len() > crate::refs::MAX_REF_NAME_BYTES)
        {
            return Err(ForkError::TooLarge);
        }
        let expected = super::accept::result(job)?;
        let accepted = job
            .accepted
            .as_ref()
            .filter(|saved| **saved == expected)
            .ok_or(ForkError::Unavailable("fork acceptance missing"))?;
        Ok(Self {
            expected: result(&expected),
            accepted: result(accepted),
            packs: inventory(job)?,
        })
    }

    /// The caller has just completed the real destination proof. Its ordinary
    /// `NotAfter` and physical authority permission remain mandatory at apply.
    pub(super) fn decide(
        &self,
        progress: &ForkAdvanceFacts,
        pack: Hash,
        rows: &[Option<Value>],
        context: mkit_primitives::fork::ForkPairContext,
        now: u64,
    ) -> Result<mkit_primitives::fork::ForkActivationDecision, ForkError> {
        use mkit_primitives::fork::{
            ForkActivationDecision, ForkActivationFacts, ForkClearanceProof, ForkMembershipUnit,
            ForkWitness, decide_fork_activation,
        };
        let expected = ForkWitness::new(
            self.expected.destination_generation,
            0,
            true,
            false,
            pack == self.expected.packmap,
        );
        let row = |value: &Option<Value>| -> Result<Option<ForkWitness>, ForkError> {
            value
                .as_ref()
                .map(|value| {
                    let witness = crate::store::publication::Witness::decode(value)
                        .map_err(|_| ForkError::NotEmpty)?;
                    // Fork replay requires the original canonical bytes. Ordinary
                    // immediate membership's empty form is a foreign value even
                    // when its decoded generation-zero fields happen to match.
                    if witness.encode() != *value {
                        return Err(ForkError::NotEmpty);
                    }
                    Ok(ForkWitness::new(
                        generation(witness.generation),
                        witness.sequence,
                        witness.published,
                        witness.held,
                        witness.boundary,
                    ))
                })
                .transpose()
        };
        let [live, published] = rows else {
            return Err(ForkError::Unavailable("fork member read"));
        };
        let unit = ForkMembershipUnit::new(
            pack,
            progress.progress.revision,
            expected,
            row(live)?,
            row(published)?,
            context,
        );
        let valid_through_ms = now.saturating_add(super::CONTENT_WINDOW);
        let proof = ForkClearanceProof::new(
            progress.destination,
            progress.binding,
            progress.progress.revision,
            pack,
            progress.progress.revision,
            valid_through_ms,
            Revision(hash(
                &[
                    progress.binding.as_slice(),
                    pack.as_slice(),
                    &valid_through_ms.to_le_bytes(),
                ]
                .concat(),
            )),
        );
        let facts = {
            let mut v = ForkActivationFacts::new(progress, &self.expected, &self.packs, &unit);
            v.lifecycle = mkit_primitives::fork::ForkLifecycleProtection::NotOffered;
            v.accepted_result = Some(&self.accepted);
            v.proof = Some(&proof);
            v
        };
        let decision = *decide_fork_activation(&facts, now, limits())
            .map_err(|_| ForkError::Unavailable("fork activation facts"))?
            .decision();
        match decision {
            ForkActivationDecision::Defer(reason) => Err(refusal(reason)),
            ForkActivationDecision::Refuse(
                mkit_primitives::fork::ForkRefusal::DestinationNotEmpty,
            ) => Err(ForkError::NotEmpty),
            ForkActivationDecision::Refuse(_) => {
                Err(ForkError::Unavailable("fork acceptance missing"))
            }
            decision => Ok(decision),
        }
    }

    pub(super) fn complete(
        &self,
        progress: &ForkAdvanceFacts,
        job: &ForkJobV1,
    ) -> Result<(), ForkError> {
        use mkit_primitives::fork::{
            ForkCompletionDecision, ForkCompletionFacts, decide_fork_completion,
        };
        let facts = {
            let mut v = ForkCompletionFacts::new(
                progress,
                &self.expected,
                u64::from(job.cursor),
                job.part,
                u64::from(job.cursor),
                job.pack_set(),
                job.binding,
            );
            v.lifecycle = mkit_primitives::fork::ForkLifecycleProtection::NotOffered;
            v.accepted_result = Some(&self.accepted);
            v
        };
        match *decide_fork_completion(&facts, limits())
            .map_err(|_| ForkError::Unavailable("fork completion facts"))?
            .decision()
        {
            ForkCompletionDecision::Complete => Ok(()),
            ForkCompletionDecision::Defer(reason) => Err(refusal(reason)),
            _ => Err(ForkError::Unavailable("fork completion pending")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::publication::Witness;
    use mkit_primitives::fork::{ForkActivationDecision, ForkPairContext};

    fn fixture(membership_generation: u64) -> Activation {
        let packs = vec![[7; 32], [8; 32]];
        let mut digest = mkit_core::hash::Hasher::new();
        for pack in &packs {
            digest.update(pack);
        }
        let result = SemanticResult::new(
            RefName("refs/heads/main".into()),
            RepositoryId([6; 32]),
            1,
            [5; 32],
            [8; 32],
            2,
            100,
            2,
            digest.finalize(),
            generation(membership_generation),
        );
        Activation {
            accepted: result.clone(),
            expected: result,
            packs,
        }
    }

    fn frozen_decision(
        rows: &[Option<Value>; 2],
        exact: &Value,
        context: ForkPairContext,
    ) -> Result<ForkActivationDecision, ForkError> {
        if rows.iter().all(|v| v.as_ref() == Some(exact)) {
            Ok(ForkActivationDecision::Replay)
        } else if context == ForkPairContext::Initial && rows.iter().all(Option::is_none) {
            Ok(ForkActivationDecision::Install)
        } else if context == ForkPairContext::AfterGuardLoss
            && rows.iter().flatten().all(|v| v == exact)
        {
            Ok(ForkActivationDecision::RetryPartial)
        } else {
            Err(ForkError::NotEmpty)
        }
    }

    #[test]
    fn activation_lowering_matches_the_frozen_reference_pair_matrix() {
        let progress = {
            let mut v = ForkAdvanceFacts::new(
                [1; 32],
                RepositoryId([2; 32]),
                ForkProgress::new(ForkAdvancePhase::Accepted, 0, 0, Revision([3; 32])),
                0,
            );
            v.recorded_authority = ForkObservation::Absent;
            v.authority = ForkObservation::Absent;
            v.grant_epoch = None;
            v.reservation = None;
            v
        };
        for membership_generation in [0, 1] {
            let activation = fixture(membership_generation);
            for pack in [[7; 32], [8; 32]] {
                let witness = Witness {
                    generation: membership_generation,
                    sequence: 0,
                    published: true,
                    held: false,
                    boundary: pack == activation.expected.packmap,
                };
                let exact = witness.encode();
                let foreign = Witness {
                    held: true,
                    ..witness
                }
                .encode();
                // The immediate-membership empty form aliases a canonical
                // generation-zero non-head witness after decoding. It remains
                // foreign to a fork under the original raw-byte contract.
                let choices = [
                    None,
                    Some(exact.clone()),
                    Some(foreign),
                    Some(Value::new(vec![255])),
                    Some(Value::default()),
                ];
                for live in &choices {
                    for published in &choices {
                        for context in [ForkPairContext::Initial, ForkPairContext::AfterGuardLoss] {
                            let rows = [live.clone(), published.clone()];
                            let expected = frozen_decision(&rows, &exact, context);
                            assert_eq!(
                                activation.decide(&progress, pack, &rows, context, 100),
                                expected,
                                "generation={membership_generation} pack={pack:?} context={context:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
