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
        .then(|| ForkEpochFence {
            recorded: observation(recorded.epoch.as_deref()),
            current: observation(rows.get(1).and_then(Option::as_ref).map(Value::as_bytes)),
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
    Ok(ForkAdvanceFacts {
        binding: job.binding,
        destination: RepositoryId(hash(destination.as_bytes())),
        progress: ForkProgress {
            phase: match job.phase {
                Phase::Done => ForkAdvancePhase::Complete,
                Phase::Failed => ForkAdvancePhase::Failed,
                _ if job.accepted.is_some() => ForkAdvancePhase::Accepted,
                _ => ForkAdvancePhase::Preparing,
            },
            cursor: u64::from(job.cursor),
            part: job.part,
            revision: Revision(hash(raw.as_bytes())),
        },
        recorded_authority: observation(job.fence_rows.authority.as_deref()),
        authority: observation(rows.first().and_then(Option::as_ref).map(Value::as_bytes)),
        grant_epoch: job
            .fence
            .as_ref()
            .is_some_and(|f| f.grant_epoch.is_some())
            .then(|| ForkEpochFence {
                recorded: observation(job.fence_rows.epoch.as_deref()),
                current: observation(rows.get(1).and_then(Option::as_ref).map(Value::as_bytes)),
            }),
        reservation: job
            .settle
            .as_ref()
            .filter(|s| job.accepted.is_none() && !s.rid.is_empty())
            .map(|s| ForkReservationFence {
                reservation: mkit_primitives::decision::ReservationId(hash(s.rid.as_bytes())),
                expected: Revision(hash(&s.pending)),
                current: observation(reservation.map(Value::as_bytes)),
            }),
        construction_expires_ms: job.expires_ms,
    })
}

pub(super) fn progress(facts: &ForkAdvanceFacts, now: u64) -> Result<(), ForkError> {
    match decide_fork_advance(facts, now).decision() {
        ForkAdvanceDecision::Advance => Ok(()),
        ForkAdvanceDecision::Refuse(reason) => Err(refusal(reason)),
        ForkAdvanceDecision::Terminal => Err(ForkError::Unavailable("fork terminal progress")),
    }
}

pub(super) fn generation(value: u64) -> Revision {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Revision(bytes)
}

pub(super) fn result(result: &ForkResult) -> SemanticResult {
    SemanticResult {
        branch: RefName(result.source_ref.clone()),
        source: RepositoryId(hash(result.source.as_bytes())),
        source_sequence: result.source_sequence,
        tip: result.tip,
        packmap: result.packmap,
        packs: result.pack_count,
        bytes: result.pack_bytes,
        index_entries: result.object_count,
        pack_digest: result.pack_set,
        destination_generation: generation(result.membership_generation),
    }
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
    mkit_primitives::fork::ForkActivationLimits {
        packs: super::MAX_FORK_PACKS as u64,
        branch_bytes: crate::refs::MAX_REF_NAME_BYTES as u64,
        work: 40_000,
    }
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
        let expected = ForkWitness {
            generation: self.expected.destination_generation,
            sequence: 0,
            published: true,
            held: false,
            boundary: pack == self.expected.packmap,
        };
        let row = |value: &Option<Value>| -> Result<Option<ForkWitness>, ForkError> {
            value
                .as_ref()
                .map(|value| {
                    crate::store::publication::Witness::decode(value)
                        .map(|w| ForkWitness {
                            generation: generation(w.generation),
                            sequence: w.sequence,
                            published: w.published,
                            held: w.held,
                            boundary: w.boundary,
                        })
                        .map_err(|_| ForkError::NotEmpty)
                })
                .transpose()
        };
        let [live, published] = rows else {
            return Err(ForkError::Unavailable("fork member read"));
        };
        let unit = ForkMembershipUnit {
            pack,
            inherited_revision: progress.progress.revision,
            expected,
            live: row(live)?,
            published: row(published)?,
            context,
        };
        let proof = ForkClearanceProof {
            destination: progress.destination,
            binding: progress.binding,
            progress_revision: progress.progress.revision,
            pack,
            // The request-local identity is scoped by the complete progress,
            // pack and deadline carried beside it. No durable proof is minted.
            apply_attempt: progress.progress.revision,
            valid_through_ms: now.saturating_add(super::CONTENT_WINDOW),
        };
        let facts = ForkActivationFacts {
            advance: progress,
            expected_result: &self.expected,
            accepted_result: Some(&self.accepted),
            inherited_packs: &self.packs,
            // Storage lifecycle transitions are outside the reference profile.
            lifecycle: mkit_primitives::fork::ForkLifecycleProtection::NotOffered,
            unit: &unit,
            proof: Some(&proof),
        };
        let decision = decide_fork_activation(&facts, now, limits())
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
        let mut progress = progress.clone();
        progress.progress.cursor = u64::from(job.cursor);
        progress.progress.part = job.part;
        let facts = ForkCompletionFacts {
            advance: &progress,
            expected_result: &self.expected,
            accepted_result: Some(&self.accepted),
            lifecycle: mkit_primitives::fork::ForkLifecycleProtection::NotOffered,
            completed_packs: u64::from(job.cursor),
            completed_digest: job.pack_set(),
            expected_barrier_owner: job.binding,
        };
        match decide_fork_completion(&facts, limits())
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

    #[test]
    fn activation_lowering_matches_the_frozen_reference_pair_matrix() {
        let mut digest = mkit_core::hash::Hasher::new();
        digest.update(&[7; 32]);
        let result = SemanticResult {
            source: RepositoryId([6; 32]),
            branch: RefName("refs/heads/main".into()),
            source_sequence: 1,
            tip: [5; 32],
            packmap: [7; 32],
            packs: 1,
            bytes: 100,
            index_entries: 2,
            pack_digest: digest.finalize(),
            destination_generation: generation(1),
        };
        let activation = Activation {
            accepted: result.clone(),
            expected: result,
            packs: vec![[7; 32]],
        };
        let progress = ForkAdvanceFacts {
            binding: [1; 32],
            destination: RepositoryId([2; 32]),
            progress: ForkProgress {
                phase: ForkAdvancePhase::Accepted,
                cursor: 0,
                part: 0,
                revision: Revision([3; 32]),
            },
            recorded_authority: ForkObservation::Absent,
            authority: ForkObservation::Absent,
            grant_epoch: None,
            reservation: None,
            construction_expires_ms: 0,
        };
        let exact = Witness {
            generation: 1,
            sequence: 0,
            published: true,
            held: false,
            boundary: true,
        }
        .encode();
        let foreign = Witness {
            generation: 1,
            sequence: 0,
            published: true,
            held: true,
            boundary: true,
        }
        .encode();
        let choices = [
            None,
            Some(exact.clone()),
            Some(foreign),
            Some(Value::new(vec![255])),
        ];
        for live in &choices {
            for published in &choices {
                for context in [ForkPairContext::Initial, ForkPairContext::AfterGuardLoss] {
                    let rows = [live.clone(), published.clone()];
                    // Frozen reference contract works on complete raw rows. The
                    // adapter independently decodes typed witnesses for the primitive.
                    let expected =
                        if live.as_ref() == Some(&exact) && published.as_ref() == Some(&exact) {
                            Ok(ForkActivationDecision::Replay)
                        } else if context == ForkPairContext::Initial
                            && live.is_none()
                            && published.is_none()
                        {
                            Ok(ForkActivationDecision::Install)
                        } else if context == ForkPairContext::AfterGuardLoss
                            && rows.iter().flatten().all(|v| *v == exact)
                        {
                            Ok(ForkActivationDecision::RetryPartial)
                        } else {
                            Err(ForkError::NotEmpty)
                        };
                    assert_eq!(
                        activation.decide(&progress, [7; 32], &rows, context, 100),
                        expected
                    );
                }
            }
        }
    }
}
