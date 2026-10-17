//! Pure publication metadata accompanying an accepted ref change.
use super::checks::failure;
use crate::{
    decision::{
        AcceptanceEffects, Guarded, Observed, PublicationEffect, PublicationFact, RequiredGuard,
        RetryReason, WriteDecision,
    },
    error::{Failure, FailureCode},
    evidence::{RepositoryId, Revision},
};
use mkit_core::hash::Hash;

/// Already verified publication intent; retained advance proofs remain host facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPublication {
    /// Exact repository.
    pub repository: RepositoryId,
    /// Resulting live head, after applying the original proposal.
    pub head: Option<Hash>,
    /// Resulting live packmap, after applying the original proposal.
    pub packmap: Option<Hash>,
    /// At least one original ref change deletes a component.
    pub deleted: bool,
    /// Existing clearance proof permits publication.
    pub publishable: bool,
    /// Existing host backlog policy; deletion bypasses this ceiling.
    pub max_unpublished: u64,
}

/// Decide publication sequence, prefix, pair and deletion boundary atomically.
///
/// ALPHA: this fragment ships check-only — the server decides with it and
/// verifies its projection, but no wire caller drives it yet. Lanes F3 and
/// C2a will call it for clearance publication and fork activation.
///
/// This fragment composes with ref acceptance in the same transaction. It emits
/// no membership, retained-advance or outcome effect. Those proofs and effects
/// belong to their owning decisions. An absent row is the only initial state.
///
/// # Errors
/// `InvalidResponse` for contradictory counters or sequence overflow. A full
/// backlog returns a retry and never terminal replay. Input/output contain at
/// most one fixed-size fact and one guard; there is no unbounded collection.
pub fn decide_ref_publication(
    request: &RefPublication,
    observed: &Observed<PublicationFact>,
) -> Result<Guarded<WriteDecision>, Failure> {
    let mut next = match observed {
        Observed::Absent(_) => PublicationFact {
            generation: Revision([0; 32]),
            sequence: 0,
            published_prefix: 0,
            deletion_boundary: 0,
            head: None,
            packmap: None,
        },
        Observed::Present { value, .. } => value.clone(),
    };
    if next.deletion_boundary > next.published_prefix || next.published_prefix > next.sequence {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let decision = if !request.deleted
        && next.sequence - next.published_prefix >= request.max_unpublished
    {
        WriteDecision::Retry(RetryReason::Unavailable)
    } else {
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        if request.deleted {
            next.deletion_boundary = next.sequence;
            next.published_prefix = next.sequence;
            // Deletion clears components immediately, never reveals a surviving
            // component from an uncleared live advance.
            next.head = request.head.and(next.head);
            next.packmap = request.packmap.and(next.packmap);
        } else if request.publishable && next.published_prefix.checked_add(1) == Some(next.sequence)
        {
            next.published_prefix = next.sequence;
            next.head = request.head;
            next.packmap = request.packmap;
        }
        WriteDecision::Apply(AcceptanceEffects {
            refs: vec![],
            membership: vec![],
            tickets: vec![],
            reservations: vec![],
            reservation_transitions: vec![],
            replay: None,
            publication: vec![PublicationEffect {
                repository: request.repository,
                next,
            }],
            accounting: vec![],
            storage: vec![],
            outcomes: vec![],
        })
    };
    Ok(Guarded {
        repository: request.repository,
        decision,
        required: vec![RequiredGuard::Publication {
            repository: request.repository,
            expected: observed.clone(),
        }],
        source_fences: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_matrix_matches_frozen_prefix_and_deletion_rules() {
        for sequence in 0..4 {
            for prefix in 0..=sequence {
                for deleted in [false, true] {
                    for publishable in [false, true] {
                        let prior = PublicationFact {
                            generation: Revision([9; 32]),
                            sequence,
                            published_prefix: prefix,
                            deletion_boundary: 0,
                            head: Some([1; 32]),
                            packmap: Some([2; 32]),
                        };
                        let observed = Observed::Present {
                            value: prior.clone(),
                            revision: Revision([3; 32]),
                        };
                        let request = RefPublication {
                            repository: RepositoryId([4; 32]),
                            head: if deleted { None } else { Some([5; 32]) },
                            packmap: Some([6; 32]),
                            deleted,
                            publishable,
                            max_unpublished: 2,
                        };
                        let result = decide_ref_publication(&request, &observed).unwrap();
                        let WriteDecision::Apply(effects) = result.decision() else {
                            assert!(!deleted && sequence - prefix >= 2);
                            continue;
                        };
                        let next = &effects.publication[0].next;
                        assert_eq!(next.sequence, sequence + 1);
                        assert_eq!(next.generation, prior.generation);
                        if deleted {
                            assert_eq!(
                                (next.deletion_boundary, next.published_prefix),
                                (sequence + 1, sequence + 1)
                            );
                            assert_eq!((next.head, next.packmap), (None, prior.packmap));
                        } else if publishable && prefix == sequence {
                            assert_eq!(next.published_prefix, sequence + 1);
                            assert_eq!((next.head, next.packmap), (request.head, request.packmap));
                        } else {
                            assert_eq!(next.published_prefix, prefix);
                            assert_eq!(next.head, prior.head);
                        }
                        super::super::check_guard_completeness(&result, result.required_guards())
                            .unwrap();
                        assert!(super::super::check_guard_completeness(&result, &[]).is_err());
                    }
                }
            }
        }
    }
}
