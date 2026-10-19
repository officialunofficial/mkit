//! Reference acquisition and lowering for the portable ref-decision fragment.
//!
//! Replay, quota, authority, ticket and publication fragments keep their
//! existing order in the enclosing planner. These functions introduce no store
//! read: they decode only acquired rows and lower every portable dependency.

use mkit_core::hash::hash;
use mkit_primitives::{
    decision::{
        Guarded, Observed, RefName, RequiredGuard, RetryReason, Snapshot as RefSnapshot,
        WriteDecision,
        ref_write::{
            AdmittedRef, MembershipWindow, RefChange, RefDecisionLimits, RefRequirements,
            RefWriteKind, RefWriteRequest, check_guard_completeness, decide_ref_write,
        },
    },
    error::FailureCode,
    evidence::{RepositoryId, Revision},
};

use super::{Snapshot, WriteKind, WriteRequest, corrupt, guard};
use crate::{
    error::{AbortCause, ServerError},
    op::PresenceRequirement,
    refs::{CasDecision, evaluate_condition},
    replay::{StoredResult, UpdateRefResult},
    store::{Precondition, Write, codec, keys},
};

/// The request remains bound to its sealed semantic decision through lowering.
/// Only a shape the wire rejects or no wire procedure emits — an unconditional
/// or `MISSING` delete, a repeated or malformed ref name, or more than two
/// changes — keeps the generic per-ref CAS decision the unextracted planner
/// used (SPEC-SERVER §3.1, "Reference-server behavior"). The shape is judged
/// before the portable decision runs; every failure of the portable decision
/// itself is an error, never a silent fallback.
pub(super) enum RefDecision<'request, 'data> {
    /// A served shape decided by the portable contract — including
    /// noncanonical but protocol-admitted pairs.
    Portable {
        request: &'request WriteRequest<'data>,
        guarded: Box<Guarded<WriteDecision>>,
    },
    /// A shape the portable contract refuses, decided by the generic CAS path.
    Generic {
        outcome: Option<StoredResult>,
        guards: Vec<Precondition>,
        writes: Vec<Write>,
    },
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
        .map(|update| RefChange::new(RefName(update.name.clone()), update.condition, update.new))
        .collect();
    // First occurrence wins, matching the planner's `find` per update; the
    // portable contract rejects duplicate admitted names.
    let mut seen = std::collections::BTreeSet::new();
    let admitted: Vec<_> = request
        .resolved_ref_updates
        .iter()
        .filter(|update| seen.insert(update.name.as_str()))
        .map(|update| {
            AdmittedRef::new(
                RefName(update.name.clone()),
                update.new,
                update.prior_present(),
            )
        })
        .collect();
    // The portable contract requires the presence guard to name a written ref;
    // the planner ignores a requirement scoped to a ref the write does not touch.
    let presence = request
        .grant
        .as_ref()
        .and_then(|grant| grant.presence_requirement.as_ref())
        .filter(|requirement| {
            let name = match requirement {
                PresenceRequirement::Absent(name) | PresenceRequirement::Present(name) => name,
            };
            request.refs.iter().any(|update| update.name == *name)
        })
        .map(|requirement| match requirement {
            PresenceRequirement::Absent(name) => (RefName(name.clone()), false),
            PresenceRequirement::Present(name) => (RefName(name.clone()), true),
        });
    // Reuse the canonical repository identity and its existing content digest
    // from repository-storage accounting. This is a local opaque handle, not
    // a new wire encoding, signing input, or hash domain.
    let identity = crate::store::repo_storage::identity(&request.namespace, request.repo);
    let repository = RepositoryId(hash(identity.as_bytes()));
    let Some(kind) = portable_kind(&changes, &admitted) else {
        return generic(request, snapshot).map(Some);
    };
    let input = {
        let mut v = RefWriteRequest::new(repository, kind, &changes, ref_requirements(), 0);
        v.operation = None;
        v.admitted = &admitted;
        v.presence = presence;
        v.signer = None;
        v.replay = None;
        v.ancestry = &[];
        v
    };
    let mut facts = ref_snapshot(repository);
    // At most two refs and two immutable admission bindings reach this adapter.
    // These local ceilings never raise a protocol or backend limit.
    let limits = RefDecisionLimits::new(16, 8, 8_192, 65_536, 512);
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
            Ok(guarded) => {
                return Ok(Some(RefDecision::Portable {
                    request,
                    guarded: Box::new(guarded),
                }));
            }
            Err(failure)
                if failure.code == FailureCode::UnavailableInput
                    && index + 1 < request.refs.len() => {}
            // The shape is portable, so any other failure is the primitive's
            // answer for these facts, not a reason to decide elsewhere.
            Err(failure) => return Err(super::ticketed_decision::failure_error(&failure)),
        }
    }
    Err(super::internal("missing portable ref decision"))
}

/// The portable request kind when the decision's shape contract admits
/// `changes`; `None` keeps the generic path.
fn portable_kind(changes: &[RefChange], admitted: &[AdmittedRef]) -> Option<RefWriteKind> {
    let deletion = changes.iter().all(|change| change.target.is_none());
    let kind = match (changes.len(), deletion) {
        (1, false) => RefWriteKind::Update,
        (1, true) => RefWriteKind::Delete,
        (2, false) => RefWriteKind::Advance,
        (2, true) => RefWriteKind::DeletePair,
        _ => return None,
    };
    portable_shape(changes, admitted).then_some(kind)
}

/// Whether the portable decision's shape contract admits `changes`: valid,
/// distinct ref names, either only exact-match deletions or only writes, and
/// an admission binding (when any) that names every change. Admission always
/// resolves every ref, so a partial binding never reaches production.
fn portable_shape(changes: &[RefChange], admitted: &[AdmittedRef]) -> bool {
    use mkit_core::refs::{RefWriteCondition, validate_ref_name};
    let distinct = changes
        .iter()
        .enumerate()
        .all(|(i, change)| changes[..i].iter().all(|other| other.name != change.name));
    let names = changes
        .iter()
        .all(|change| change.name.0.starts_with("refs/") && validate_ref_name(&change.name.0));
    let deletes = changes.iter().all(|change| {
        change.target.is_none() && matches!(change.condition, RefWriteCondition::Match(_))
    });
    let covered = admitted.is_empty()
        || changes
            .iter()
            .all(|change| admitted.iter().any(|entry| entry.name == change.name));
    distinct
        && names
        && covered
        && (deletes || changes.iter().all(|change| change.target.is_some()))
}

/// Generic per-ref CAS decision for served shapes the portable contract does
/// not express. Reproduces the unextracted planner exactly: grant presence
/// checks first, then each update in request order — commit guards and writes
/// on success, the first conflict's guard and outcome otherwise.
fn generic<'request, 'data>(
    request: &'request WriteRequest<'data>,
    snapshot: &Snapshot,
) -> Result<RefDecision<'request, 'data>, ServerError> {
    let mut guards = Vec::new();
    let mut writes = Vec::new();
    for (i, update) in request.refs.iter().enumerate() {
        let key = keys::ref_key(request.repo, &update.name);
        let current = snapshot
            .get(&key)
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(corrupt)?;
        let resolved = request
            .resolved_ref_updates
            .iter()
            .find(|resolved| resolved.name == update.name);
        if let Some(requirement) = request
            .grant
            .as_ref()
            .and_then(|grant| grant.presence_requirement.as_ref())
        {
            let required = match requirement {
                PresenceRequirement::Absent(name) if name == &update.name => Some(false),
                PresenceRequirement::Present(name) if name == &update.name => Some(true),
                _ => None,
            };
            if let Some(required) = required {
                if current.is_some() != required {
                    return Err(ServerError::permission_denied(
                        "write grant rejected: ref scope",
                    ));
                }
                if resolved.is_none() {
                    guards.push(if required {
                        Precondition::Present(key.clone())
                    } else {
                        Precondition::Absent(key.clone())
                    });
                }
            }
        }
        match evaluate_condition(current.as_ref(), &update.condition) {
            CasDecision::Committed => {
                if let Some(resolved) = resolved {
                    if resolved.new != update.new || resolved.prior_present() != current.is_some() {
                        return Err(ServerError::aborted_retryable(
                            "ref changed after admission; retry",
                        )
                        .with_abort_cause(AbortCause::RefConflict));
                    }
                    if update.condition == mkit_core::refs::RefWriteCondition::Any {
                        guards.push(if resolved.prior_present() {
                            Precondition::Present(key.clone())
                        } else {
                            Precondition::Absent(key.clone())
                        });
                    }
                }
                if update.condition != mkit_core::refs::RefWriteCondition::Any {
                    guards.push(guard(key.clone(), snapshot));
                }
                writes.push(match update.new {
                    Some(id) => Write::Put(key, codec::encode_ref_id(&id)),
                    None => Write::Delete(key),
                });
            }
            CasDecision::Conflict(_) => {
                guards.push(guard(key, snapshot));
                let outcome = match (request.kind, i) {
                    (WriteKind::UpdateRef, _) => {
                        StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                    }
                    (WriteKind::AdvanceRefs, 0) => StoredResult::AdvanceRefs(
                        mkit_core::protocol::AdvanceOutcome::PackmapConflict,
                    ),
                    _ => {
                        StoredResult::AdvanceRefs(mkit_core::protocol::AdvanceOutcome::HeadConflict)
                    }
                };
                return Ok(RefDecision::Generic {
                    outcome: Some(outcome),
                    guards,
                    writes: Vec::new(),
                });
            }
            CasDecision::Invalid(message) => {
                return Err(ServerError::invalid_argument(message));
            }
        }
    }
    Ok(RefDecision::Generic {
        outcome: None,
        guards,
        writes,
    })
}

/// Lower exact typed ref guards/effects; unsupported categories fail closed.
pub(super) fn lower(
    decision: RefDecision<'_, '_>,
    preconditions: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let (request, guarded) = match decision {
        RefDecision::Portable { request, guarded } => (request, guarded),
        RefDecision::Generic {
            outcome,
            guards,
            writes,
        } => {
            preconditions.extend(guards);
            return Ok((outcome, writes));
        }
    };
    let required = lower_guards(request, &guarded)?;
    let result = match guarded.decision() {
        WriteDecision::Apply(effects) => {
            if !effects.refs.iter().all(|effect| {
                request
                    .refs
                    .iter()
                    .any(|update| update.name == effect.name.0)
            }) {
                return Err(super::internal("portable ref decision out of scope"));
            }
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
                WriteKind::AdvanceRefs => {
                    // Outcome names are positional, matching the reference
                    // planner: the first change whose condition conflicts
                    // with the observed value is the conflicting slot.
                    match request.refs.iter().position(|update| {
                        update.name == observed.name.0
                            && matches!(
                                evaluate_condition(observed.value.as_ref(), &update.condition,),
                                CasDecision::Conflict(_)
                            )
                    }) {
                        Some(0) => StoredResult::AdvanceRefs(
                            mkit_core::protocol::AdvanceOutcome::PackmapConflict,
                        ),
                        Some(_) => StoredResult::AdvanceRefs(
                            mkit_core::protocol::AdvanceOutcome::HeadConflict,
                        ),
                        None => return Err(super::internal("unmatched ref conflict")),
                    }
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
        WriteDecision::Retry(RetryReason::AdmittedRefChanged) => {
            return Err(
                ServerError::aborted_retryable("ref changed after admission; retry")
                    .with_abort_cause(AbortCause::RefConflict),
            );
        }
        WriteDecision::Retry(_) => return Err(super::internal("unexpected portable ref retry")),
        _ => return Err(super::internal("unsupported portable ref decision")),
    };
    preconditions.extend(required);
    Ok(result)
}

fn ref_requirements() -> RefRequirements<'static> {
    {
        let mut v = RefRequirements::new(MembershipWindow::Elapsed);
        v.authority = None;
        v.grant = None;
        v.incarnation = None;
        v.policy = None;
        v.admission = None;
        v.members = &[];
        v.indexed_head = false;
        v.denial = false;
        v.publication = false;
        v.source = None;
        v.valid_through_ms = None;
        v
    }
}

fn ref_snapshot(repository: RepositoryId) -> RefSnapshot {
    RefSnapshot::new(repository)
}

/// The guard sealed for `name`'s value expectation, when the decision took one.
fn ref_value<'g>(
    guarded: &'g Guarded<WriteDecision>,
    name: &str,
) -> Option<&'g Observed<mkit_core::hash::Hash>> {
    guarded
        .required_guards()
        .iter()
        .find_map(|guard| match guard {
            RequiredGuard::RefValue {
                name: candidate,
                expected,
                ..
            } if candidate.0 == name => Some(expected),
            _ => None,
        })
}

fn push_value(
    required: &mut Vec<Precondition>,
    key: crate::store::Key,
    expected: &Observed<mkit_core::hash::Hash>,
) -> Result<(), ServerError> {
    required.push(match expected {
        Observed::Absent(_) => Precondition::Absent(key),
        Observed::Present { value, .. } => Precondition::Equals(key, codec::encode_ref_id(value)),
        _ => return Err(super::internal("unsupported ref observation")),
    });
    Ok(())
}

/// Emit each processed update's guards in request order. The reference guards
/// every update it evaluates, so a repeated name contributes once per slot; a
/// conflict bounds the processed prefix at the first failing condition.
pub(super) fn lower_ref_slots(
    request: &WriteRequest<'_>,
    guarded: &Guarded<WriteDecision>,
    required: &mut Vec<Precondition>,
) -> Result<(), ServerError> {
    let boundary = if matches!(guarded.decision(), WriteDecision::Conflict { .. }) {
        let mut found = None;
        for (index, update) in request.refs.iter().enumerate() {
            if update.condition == mkit_core::refs::RefWriteCondition::Any {
                continue;
            }
            let expected = ref_value(guarded, &update.name)
                .ok_or_else(|| super::internal("missing portable ref guard"))?;
            let current = match expected {
                Observed::Present { value, .. } => Some(*value),
                Observed::Absent(_) => None,
                _ => return Err(super::internal("unsupported ref observation")),
            };
            if matches!(
                evaluate_condition(current.as_ref(), &update.condition),
                CasDecision::Conflict(_)
            ) {
                found = Some(index + 1);
                break;
            }
        }
        found.ok_or_else(|| super::internal("unmatched ref conflict"))?
    } else {
        request.refs.len()
    };
    for update in &request.refs[..boundary] {
        let key = keys::ref_key(request.repo, &update.name);
        // A sealed presence guard is discharged by the slot's own CAS when
        // admission already resolved it under a real condition.
        let covered = update.condition != mkit_core::refs::RefWriteCondition::Any
            && ref_value(guarded, &update.name).is_some()
            && request
                .resolved_ref_updates
                .iter()
                .any(|resolved| resolved.name == update.name);
        let presence = guarded
            .required_guards()
            .iter()
            .find_map(|guard| match guard {
                RequiredGuard::RefPresence { name, present, .. } if name.0 == update.name => {
                    Some(*present)
                }
                _ => None,
            });
        if let (Some(present), false) = (presence, covered) {
            required.push(if present {
                Precondition::Present(key.clone())
            } else {
                Precondition::Absent(key.clone())
            });
        }
        if update.condition != mkit_core::refs::RefWriteCondition::Any {
            match ref_value(guarded, &update.name) {
                Some(expected) => push_value(required, key, expected)?,
                None => return Err(super::internal("missing portable ref guard")),
            }
        }
    }
    Ok(())
}

fn lower_guards(
    request: &WriteRequest<'_>,
    guarded: &Guarded<WriteDecision>,
) -> Result<Vec<Precondition>, ServerError> {
    for requirement in guarded.required_guards() {
        match requirement {
            RequiredGuard::RefValue { repository, .. }
            | RequiredGuard::RefPresence { repository, .. }
                if *repository == guarded.repository() => {}
            _ => return Err(super::internal("unsupported portable ref guard")),
        }
    }
    let mut required = Vec::new();
    if matches!(
        guarded.decision(),
        WriteDecision::Apply(_) | WriteDecision::Conflict { .. }
    ) {
        lower_ref_slots(request, guarded, &mut required)?;
    } else {
        // Terminal classes emit each sealed guard once; the preconditions are
        // checked for completeness but never committed.
        for requirement in guarded.required_guards() {
            match requirement {
                RequiredGuard::RefValue { name, expected, .. } => {
                    let key = keys::ref_key(request.repo, &name.0);
                    push_value(&mut required, key, expected)?;
                }
                RequiredGuard::RefPresence { name, present, .. } => {
                    required.push(if *present {
                        Precondition::Present(keys::ref_key(request.repo, &name.0))
                    } else {
                        Precondition::Absent(keys::ref_key(request.repo, &name.0))
                    });
                }
                _ => return Err(super::internal("unsupported portable ref guard")),
            }
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
