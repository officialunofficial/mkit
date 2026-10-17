//! Reference acquisition and lowering for the portable ref-decision fragment.
//!
//! Replay, quota, authority, ticket and publication fragments keep their
//! existing order in the enclosing planner. These functions introduce no store
//! read: they decode only acquired rows and lower every portable dependency.

use mkit_core::hash::hash;
use mkit_primitives::{
    decision::{
        Guarded, Observed, RefName, RequiredGuard, Snapshot as RefSnapshot, WriteDecision,
        ref_write::{
            AdmittedRef, MembershipWindow, RefChange, RefDecisionLimits, RefRequirements,
            RefWriteKind, RefWriteRequest, check_guard_completeness, decide_ref_write,
        },
    },
    error::FailureCode,
    evidence::{RepositoryId, Revision},
};

use super::{Snapshot, WriteKind, WriteRequest, corrupt};
use crate::{
    error::{AbortCause, ServerError},
    op::PresenceRequirement,
    replay::{StoredResult, UpdateRefResult},
    store::{Precondition, Write, codec, keys},
};

/// The request remains bound to its sealed semantic decision through lowering.
pub(super) struct RefDecision<'request, 'data> {
    request: &'request WriteRequest<'data>,
    guarded: Guarded<WriteDecision>,
}

/// Decode the examined prefix only, preserving first-conflict fault precedence.
pub(super) fn decide<'request, 'data>(
    request: &'request WriteRequest<'data>,
    snapshot: &Snapshot,
) -> Result<Option<RefDecision<'request, 'data>>, ServerError> {
    if request.refs.is_empty() {
        return Ok(None);
    }
    let changes: Vec<_> = request
        .refs
        .iter()
        .map(|update| RefChange {
            name: RefName(update.name.clone()),
            condition: update.condition,
            target: update.new,
        })
        .collect();
    let admitted: Vec<_> = request
        .resolved_ref_updates
        .iter()
        .map(|update| AdmittedRef {
            name: RefName(update.name.clone()),
            target: update.new,
            prior_present: update.prior_present(),
        })
        .collect();
    let presence = request
        .grant
        .as_ref()
        .and_then(|grant| grant.presence_requirement.as_ref())
        .map(|requirement| match requirement {
            PresenceRequirement::Absent(name) => (RefName(name.clone()), false),
            PresenceRequirement::Present(name) => (RefName(name.clone()), true),
        });
    // Reuse the canonical repository identity and its existing content digest
    // from repository-storage accounting. This is a local opaque handle, not
    // a new wire encoding, signing input, or hash domain.
    let identity = crate::store::repo_storage::identity(&request.namespace, request.repo);
    let repository = RepositoryId(hash(identity.as_bytes()));
    let deletion = changes.iter().all(|change| change.target.is_none());
    let kind = match (changes.len(), deletion) {
        (1, false) => RefWriteKind::Update,
        (1, true) => RefWriteKind::Delete,
        (2, false) => RefWriteKind::Advance,
        (2, true) => RefWriteKind::DeletePair,
        _ => return Err(super::internal("invalid ref decision shape")),
    };
    let input = RefWriteRequest {
        repository,
        operation: None,
        kind,
        changes: &changes,
        admitted: &admitted,
        presence,
        signer: None,
        replay: None,
        ancestry: &[],
        now_ms: 0,
        required: ref_requirements(),
    };
    let mut facts = ref_snapshot(repository);
    // At most two refs and two immutable admission bindings reach this adapter.
    // These local ceilings never raise a protocol or backend limit.
    let limits = RefDecisionLimits {
        facts: 16,
        guards: 8,
        bytes: 8_192,
        work: 65_536,
        public_message_bytes: 512,
    };
    for (index, update) in request.refs.iter().enumerate() {
        let key = keys::ref_key(request.repo, &update.name);
        if !snapshot.contains(&key) {
            return Err(super::internal("unacquired ref observation"));
        }
        let current = snapshot
            .get(&key)
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(corrupt)?;
        let observed = current.map_or(Observed::Absent(Revision([0; 32])), |value| {
            Observed::Present {
                value,
                revision: Revision(value),
            }
        });
        facts.refs.push((RefName(update.name.clone()), observed));
        match decide_ref_write(&input, &facts, limits) {
            Ok(guarded) => return Ok(Some(RefDecision { request, guarded })),
            Err(failure)
                if failure.code == FailureCode::UnavailableInput
                    && index + 1 < request.refs.len() => {}
            Err(failure) => {
                return Err(super::internal(failure.code.as_str()));
            }
        }
    }
    Err(super::internal("missing portable ref decision"))
}

/// Lower exact typed ref guards/effects; unsupported categories fail closed.
pub(super) fn lower(
    decision: RefDecision<'_, '_>,
    preconditions: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let RefDecision { request, guarded } = decision;
    let required = lower_guards(request, &guarded)?;
    let result = match guarded.decision() {
        WriteDecision::Apply(effects) => {
            let writes = effects
                .refs
                .iter()
                .map(|effect| {
                    let key = keys::ref_key(request.repo, &effect.name.0);
                    effect.target.map_or(Write::Delete(key.clone()), |value| {
                        Write::Put(key, codec::encode_ref_id(&value))
                    })
                })
                .collect();
            (None, writes)
        }
        WriteDecision::Conflict { current, .. } => {
            let observed = current
                .last()
                .ok_or_else(|| super::internal("missing ref conflict"))?;
            let result = match request.kind {
                WriteKind::UpdateRef => StoredResult::UpdateRef(UpdateRefResult::Conflict {
                    current: observed.value,
                }),
                WriteKind::AdvanceRefs if observed.name.0 == request.refs[0].name => {
                    StoredResult::AdvanceRefs(mkit_core::protocol::AdvanceOutcome::PackmapConflict)
                }
                WriteKind::AdvanceRefs => {
                    StoredResult::AdvanceRefs(mkit_core::protocol::AdvanceOutcome::HeadConflict)
                }
                _ => return Err(super::internal("unexpected ref conflict kind")),
            };
            (Some(result), Vec::new())
        }
        WriteDecision::Reject { refusal, .. } => {
            return Err(match refusal.code {
                mkit_primitives::decision::PermanentCode::PermissionDenied => {
                    ServerError::permission_denied(refusal.public_message.clone())
                }
                _ => return Err(super::internal("unsupported portable ref refusal")),
            });
        }
        WriteDecision::Retry(_) => {
            return Err(
                ServerError::aborted_retryable("ref changed after admission; retry")
                    .with_abort_cause(AbortCause::RefConflict),
            );
        }
        _ => return Err(super::internal("unsupported portable ref decision")),
    };
    preconditions.extend(required);
    Ok(result)
}

fn ref_requirements() -> RefRequirements<'static> {
    RefRequirements {
        authority: None,
        grant: None,
        incarnation: None,
        policy: None,
        admission: None,
        members: &[],
        indexed_head: false,
        membership_window: MembershipWindow::Elapsed,
        denial: false,
        publication: false,
        source: None,
        valid_through_ms: None,
    }
}

fn ref_snapshot(repository: RepositoryId) -> RefSnapshot {
    RefSnapshot {
        repository,
        refs: Vec::new(),
        replay: None,
        tickets: Vec::new(),
        reservations: Vec::new(),
        authority: None,
        grant: None,
        lifecycle: None,
        members: Vec::new(),
        denial: None,
        policy: None,
        admission: None,
        accounting: None,
        publication: None,
    }
}

fn lower_guards(
    request: &WriteRequest<'_>,
    guarded: &Guarded<WriteDecision>,
) -> Result<Vec<Precondition>, ServerError> {
    let mut required = Vec::new();
    for requirement in guarded.required_guards() {
        match requirement {
            RequiredGuard::RefValue {
                repository,
                name,
                expected,
            } if *repository == guarded.repository() => {
                let key = keys::ref_key(request.repo, &name.0);
                required.push(match expected {
                    Observed::Absent(_) => Precondition::Absent(key),
                    Observed::Present { value, .. } => {
                        Precondition::Equals(key, codec::encode_ref_id(value))
                    }
                    _ => return Err(super::internal("unsupported ref observation")),
                });
            }
            RequiredGuard::RefPresence {
                repository,
                name,
                present,
            } if *repository == guarded.repository() => {
                // The exact CAS already discharges admission's presence guard.
                // Preserve the reference batch shape instead of adding another
                // backend condition for the same conditional admission fact.
                let covered = request
                    .resolved_ref_updates
                    .iter()
                    .any(|update| update.name == name.0)
                    && request.refs.iter().any(|update| {
                        update.name == name.0
                            && update.condition != mkit_core::refs::RefWriteCondition::Any
                    })
                    && guarded.required_guards().iter().any(|guard| {
                        matches!(guard,
                        RequiredGuard::RefValue { name: key, .. } if key == name)
                    });
                if !covered {
                    let key = keys::ref_key(request.repo, &name.0);
                    required.push(if *present {
                        Precondition::Present(key)
                    } else {
                        Precondition::Absent(key)
                    });
                }
            }
            _ => return Err(super::internal("unsupported portable ref guard")),
        }
    }
    let discharged: Vec<_> = guarded
        .required_guards()
        .iter()
        .filter(|guard| projects(guard, request, &required))
        .cloned()
        .collect();
    check_guard_completeness(guarded, &discharged)
        .map_err(|failure| super::internal(failure.code.as_str()))?;
    Ok(required)
}

fn projects(
    guard: &RequiredGuard,
    request: &WriteRequest<'_>,
    conditions: &[Precondition],
) -> bool {
    match guard {
        RequiredGuard::RefValue { name, expected, .. } => {
            let key = keys::ref_key(request.repo, &name.0);
            match expected {
                Observed::Absent(_) => conditions.contains(&Precondition::Absent(key)),
                Observed::Present { value, .. } => {
                    conditions.contains(&Precondition::Equals(key, codec::encode_ref_id(value)))
                }
                _ => false,
            }
        }
        RequiredGuard::RefPresence { name, present, .. } => {
            let key = keys::ref_key(request.repo, &name.0);
            conditions.iter().any(|condition| match condition {
                Precondition::Absent(candidate) => !*present && *candidate == key,
                Precondition::Present(candidate) => *present && *candidate == key,
                Precondition::Equals(candidate, value) => {
                    *present && *candidate == key && codec::decode_ref_id(value).is_ok()
                }
                Precondition::NotAfter(_) => false,
            })
        }
        _ => false,
    }
}
