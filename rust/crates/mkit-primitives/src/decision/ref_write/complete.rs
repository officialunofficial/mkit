use crate::{
    decision::{
        AcceptanceEffects, DecisionClass, GuardKind, Guarded, RequiredGuard, WriteDecision,
    },
    error::{Failure, FailureCode},
};

use super::checks::failure;

/// Current semantic guard-requirements ruleset. This defines no byte encoding.
pub const GUARD_REQUIREMENTS_VERSION: u32 = 1;

/// Reject an adapter's unknown guard category or unsupported requirements version.
///
/// Adapters preserve an unrecognized category as `None`, rather than dropping
/// it. No numeric category assignments or transport encoding are defined here.
/// Exhaustive matching also makes adding a category require an explicit ruleset
/// decision in this crate.
///
/// # Errors
/// `UnsupportedCapability` for an unknown category or version.
pub fn validate_guard_kind(kind: Option<GuardKind>, version: u32) -> Result<GuardKind, Failure> {
    if version != GUARD_REQUIREMENTS_VERSION {
        return Err(failure(FailureCode::UnsupportedCapability));
    }
    match kind {
        Some(
            kind @ (GuardKind::RefValue
            | GuardKind::RefPresence
            | GuardKind::Replay
            | GuardKind::Ticket
            | GuardKind::Reservation
            | GuardKind::Authority
            | GuardKind::Grant
            | GuardKind::Repository
            | GuardKind::Membership
            | GuardKind::Denial
            | GuardKind::Policy
            | GuardKind::Admission
            | GuardKind::Accounting
            | GuardKind::Storage
            | GuardKind::Publication
            | GuardKind::ValidThrough),
        ) => Ok(kind),
        None => Err(failure(FailureCode::UnsupportedCapability)),
    }
}

/// Category of an exact typed guard. Exact-key completeness remains separate.
#[must_use]
pub const fn guard_kind(guard: &RequiredGuard) -> GuardKind {
    match guard {
        RequiredGuard::RefValue { .. } => GuardKind::RefValue,
        RequiredGuard::RefPresence { .. } => GuardKind::RefPresence,
        RequiredGuard::Replay { .. } => GuardKind::Replay,
        RequiredGuard::Ticket { .. } => GuardKind::Ticket,
        RequiredGuard::Reservation { .. } => GuardKind::Reservation,
        RequiredGuard::Authority { .. } => GuardKind::Authority,
        RequiredGuard::Grant { .. } => GuardKind::Grant,
        RequiredGuard::Repository { .. } => GuardKind::Repository,
        RequiredGuard::Membership { .. } => GuardKind::Membership,
        RequiredGuard::Denial { .. } => GuardKind::Denial,
        RequiredGuard::Policy { .. } => GuardKind::Policy,
        RequiredGuard::Admission { .. } => GuardKind::Admission,
        RequiredGuard::Accounting { .. } => GuardKind::Accounting,
        RequiredGuard::Storage { .. } => GuardKind::Storage,
        RequiredGuard::Publication { .. } => GuardKind::Publication,
        RequiredGuard::ValidThrough { .. } => GuardKind::ValidThrough,
    }
}

/// Kind-level completeness over bare effects.
///
/// An embedder composing extra effects under SPEC-SERVER §10.4 has only the
/// `AcceptanceEffects`, not a sealed decision: this is the intrinsic effect
/// rule for that composition. The stronger sealed-decision rule is
/// [`required_guard_kinds`], which calls this and adds the refusal-only
/// dependencies the artifact retains.
///
/// # Errors
/// `InvalidResponse` when a non-Apply class still carries mutations;
/// `ResourceLimit` if the bounded category collection cannot be allocated.
pub fn effect_guard_kinds(
    class: &DecisionClass,
    effects: &AcceptanceEffects,
) -> Result<Vec<GuardKind>, Failure> {
    let writes = !effects.refs.is_empty()
        || !effects.membership.is_empty()
        || !effects.tickets.is_empty()
        || !effects.publication.is_empty()
        || !effects.accounting.is_empty()
        || !effects.storage.is_empty()
        || !effects.reservation_transitions.is_empty();
    if !matches!(class, DecisionClass::Apply) && writes {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let mut kinds = Vec::new();
    kinds
        .try_reserve_exact(15)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    let mut add = |kind| {
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    };
    if matches!(class, DecisionClass::Conflict) {
        add(GuardKind::RefValue);
    }
    if matches!(class, DecisionClass::ReturnRecorded) || effects.replay.is_some() {
        add(GuardKind::Replay);
    }
    if !effects.membership.is_empty() {
        add(GuardKind::Membership);
    }
    if !effects.tickets.is_empty() {
        add(GuardKind::Ticket);
    }
    if !effects.reservations.is_empty()
        || !effects.reservation_transitions.is_empty()
        || !effects.outcomes.is_empty()
    {
        add(GuardKind::Reservation);
    }
    if !effects.publication.is_empty() {
        add(GuardKind::Publication);
    }
    if !effects.accounting.is_empty() {
        add(GuardKind::Accounting);
    }
    if !effects.storage.is_empty() {
        add(GuardKind::Storage);
    }
    Ok(kinds)
}

/// Kind-level completeness over a sealed decision and its read dependencies.
///
/// Bare `AcceptanceEffects` are insufficient: an unconditional write and a CAS
/// can have identical mutations, and a refusal can have no mutations at all.
/// The sealed artifact retains those distinctions, including refusal-only facts.
/// Intrinsic effect requirements are checked independently of the emitted list.
/// Exact keyed completeness is additionally enforced by `check_guard_completeness`.
///
/// # Errors
/// `InvalidResponse` for a mismatched decision class or inconsistent effects;
/// `ResourceLimit` if the bounded category collection cannot be allocated.
pub fn required_guard_kinds(
    class: &DecisionClass,
    effects: &Guarded<WriteDecision>,
) -> Result<Vec<GuardKind>, Failure> {
    if *class != decision_class(effects.decision()) {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let empty = AcceptanceEffects {
        refs: Vec::new(),
        membership: Vec::new(),
        tickets: Vec::new(),
        reservations: Vec::new(),
        reservation_transitions: Vec::new(),
        replay: None,
        publication: Vec::new(),
        accounting: Vec::new(),
        storage: Vec::new(),
        outcomes: Vec::new(),
    };
    let mutations = match effects.decision() {
        WriteDecision::Apply(mutations) => mutations,
        _ => &empty,
    };
    let mut kinds = effect_guard_kinds(class, mutations)?;
    if matches!(
        effects.decision(),
        WriteDecision::Reject {
            terminal: Some(_),
            ..
        } | WriteDecision::Conflict {
            replay: Some(_),
            ..
        }
    ) && !kinds.contains(&GuardKind::Replay)
    {
        kinds.push(GuardKind::Replay);
    }
    for dependency in effects.required_guards() {
        let kind = guard_kind(dependency);
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    Ok(kinds)
}

fn decision_class(decision: &WriteDecision) -> DecisionClass {
    match decision {
        WriteDecision::Apply(_) => DecisionClass::Apply,
        WriteDecision::Conflict { .. } => DecisionClass::Conflict,
        WriteDecision::Reject { .. } => DecisionClass::Reject,
        WriteDecision::ReturnRecorded(_) => DecisionClass::ReturnRecorded,
        WriteDecision::Retry(_) => DecisionClass::Retry,
    }
}

/// Check every exact dependency before lowering a sealed decision.
///
/// This compares keys and values, not just categories: dropping one of two ref
/// guards is an omission even though the category still appears. Extra host
/// safety guards are allowed. The sealed dependency set comes from the pure
/// decision; it cannot be supplied by untrusted evidence decoding.
///
/// # Errors
/// `InvalidResponse` for an omitted exact dependency or a contradictory guard.
pub fn check_guard_completeness(
    decision: &Guarded<WriteDecision>,
    lowered: &[RequiredGuard],
) -> Result<(), Failure> {
    for (i, guard) in lowered.iter().enumerate() {
        if lowered[..i].iter().any(|other| !compatible(other, guard)) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for expected in decision.required_guards() {
        if !lowered.contains(expected) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    let class = decision_class(decision.decision());
    for kind in required_guard_kinds(&class, decision)? {
        if !lowered.iter().any(|guard| guard_kind(guard) == kind) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    Ok(())
}

fn compatible(left: &RequiredGuard, right: &RequiredGuard) -> bool {
    use RequiredGuard as G;
    match (left, right) {
        (
            G::RefValue {
                repository: a,
                name: x,
                expected,
            },
            G::RefPresence {
                repository: b,
                name: y,
                present,
            },
        )
        | (
            G::RefPresence {
                repository: b,
                name: y,
                present,
            },
            G::RefValue {
                repository: a,
                name: x,
                expected,
            },
        ) if a == b && x == y => {
            matches!(expected, crate::decision::Observed::Present { .. }) == *present
        }
        _ if same_identity(left, right) => left == right,
        _ => true,
    }
}

fn same_identity(left: &RequiredGuard, right: &RequiredGuard) -> bool {
    use RequiredGuard as G;
    match (left, right) {
        (
            G::RefValue {
                repository: a,
                name: x,
                ..
            },
            G::RefValue {
                repository: b,
                name: y,
                ..
            },
        )
        | (
            G::RefPresence {
                repository: a,
                name: x,
                ..
            },
            G::RefPresence {
                repository: b,
                name: y,
                ..
            },
        ) => a == b && x == y,
        (G::Replay { scope: a, .. }, G::Replay { scope: b, .. }) => a == b,
        (G::Ticket { id: a, .. }, G::Ticket { id: b, .. }) => a == b,
        (G::Reservation { id: a, .. }, G::Reservation { id: b, .. }) => a == b,
        (G::Authority { namespace: a, .. }, G::Authority { namespace: b, .. })
        | (G::Grant { namespace: a, .. }, G::Grant { namespace: b, .. }) => a == b,
        (
            G::Membership {
                repository: a,
                object: x,
                ..
            },
            G::Membership {
                repository: b,
                object: y,
                ..
            },
        ) => a == b && x == y,
        (G::Repository { id: a, .. }, G::Repository { id: b, .. })
        | (G::Denial { repository: a, .. }, G::Denial { repository: b, .. })
        | (G::Policy { repository: a, .. }, G::Policy { repository: b, .. })
        | (G::Accounting { repository: a, .. }, G::Accounting { repository: b, .. })
        | (G::Storage { repository: a, .. }, G::Storage { repository: b, .. })
        | (G::Publication { repository: a, .. }, G::Publication { repository: b, .. }) => a == b,
        (G::Admission { operation: a, .. }, G::Admission { operation: b, .. }) => a == b,
        // Independent upper bounds compose by taking their minimum.
        _ => false,
    }
}
