use super::{RefDecisionLimits, RefWriteRequest};
use crate::{
    decision::{Observed, RequiredGuard, Snapshot, TerminalResult},
    error::{BoundedDetail, Failure, FailureCode, Location},
};

pub(crate) fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

pub(crate) fn bounds(
    request: &RefWriteRequest<'_>,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<(), Failure> {
    let facts = fact_count(request, snapshot)?;
    let cost = facts
        .checked_mul(facts)
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(64));
    if facts > limits.facts as usize || cost.is_none_or(|n| n as u64 > limits.work) {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let bytes = input_bytes(request, snapshot, limits)?;
    if cost
        .and_then(|work| {
            (facts as u64)
                .checked_add(2)
                .and_then(|factor| bytes.checked_mul(factor))
                .and_then(|variable| (work as u64).checked_add(variable))
        })
        .is_none_or(|work| work > limits.work)
    {
        return Err(failure(FailureCode::ResourceLimit));
    }
    if snapshot.repository != request.repository {
        return Err(failure(FailureCode::InvalidResponse));
    }
    unambiguous(request, snapshot)
}

fn fact_count(request: &RefWriteRequest<'_>, snapshot: &Snapshot) -> Result<usize, Failure> {
    let mut facts = snapshot
        .refs
        .len()
        .checked_add(snapshot.members.len())
        .and_then(|n| n.checked_add(snapshot.tickets.len()))
        .and_then(|n| n.checked_add(snapshot.reservations.len()))
        .and_then(|n| n.checked_add(request.ancestry.len()))
        .and_then(|n| n.checked_add(request.required.members.len()))
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    let mut count = |n: usize| -> Result<(), Failure> {
        facts = facts
            .checked_add(n)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(())
    };
    count(request.changes.len())?;
    count(request.admitted.len())?;
    count(
        [
            snapshot.replay.is_some(),
            snapshot.authority.is_some(),
            snapshot.grant.is_some(),
            snapshot.lifecycle.is_some(),
            snapshot.denial.is_some(),
            snapshot.policy.is_some(),
            snapshot.admission.is_some(),
            snapshot.accounting.is_some(),
            snapshot.storage.is_some(),
            snapshot.publication.is_some(),
            request.required.source.is_some(),
            request.presence.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count(),
    )?;
    for (_, observed) in &snapshot.reservations {
        if let Observed::Present {
            value: crate::decision::ReservationFact::Terminal(terminal),
            ..
        } = observed
            && let crate::decision::ReservationTerminalKind::Committed { refs, .. } = &terminal.kind
        {
            count(refs.len())?;
        }
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.policy {
        count(value.allowed_signers.len())?;
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.admission {
        count(value.presence.len())?;
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.denial {
        for set in [&value.objects, &value.packs, &value.held] {
            count(set.len())?;
        }
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.replay
        && let crate::decision::ReplayState::Committed(
            TerminalResult::Applied(refs) | TerminalResult::Conflict(refs),
        ) = &value.state
    {
        count(refs.len())?;
    }
    Ok(facts)
}

fn input_bytes(
    request: &RefWriteRequest<'_>,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<u64, Failure> {
    let mut bytes = 0_u64;
    let mut add = |n: usize| -> Result<(), Failure> {
        bytes = bytes
            .checked_add(n as u64)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if bytes > limits.bytes {
            return Err(failure(FailureCode::ResourceLimit));
        }
        Ok(())
    };
    for change in request.changes {
        add(change.name.0.len())?;
    }
    for (name, _) in &snapshot.refs {
        add(name.0.len())?;
    }
    for (_, observed) in &snapshot.tickets {
        add(32)?;
        if let Observed::Present { value, .. } = observed {
            add(value.name.0.len())?;
            add(value.upload_session.as_ref().map_or(0, Vec::len))?;
        }
    }
    add(reservation_bytes(snapshot)?)?;
    if let Some((name, _)) = &request.presence {
        add(name.0.len())?;
    }
    for proof in request.ancestry {
        add(proof.name.0.len())?;
    }
    for change in request.admitted {
        add(change.name.0.len())?;
    }
    if let Some(source) = request.required.source {
        add(source.name.0.len())?;
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.policy {
        add(value
            .allowed_signers
            .len()
            .checked_mul(32)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?)?;
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.denial {
        for set in [&value.objects, &value.packs, &value.held] {
            add(set
                .len()
                .checked_mul(32)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?)?;
        }
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.admission {
        for delta in &value.presence {
            add(delta.name.0.len())?;
        }
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.replay
        && let crate::decision::ReplayState::Committed(result) = &value.state
    {
        match result {
            TerminalResult::Applied(refs) | TerminalResult::Conflict(refs) => {
                for value in refs {
                    add(value.name.0.len())?;
                }
            }
            TerminalResult::Rejected(refusal) => {
                add(refusal.public_message.len())?;
                if refusal.public_message.len() > limits.public_message_bytes as usize {
                    return Err(failure(FailureCode::ResourceLimit));
                }
            }
        }
    }
    Ok(bytes)
}

fn reservation_bytes(snapshot: &Snapshot) -> Result<usize, Failure> {
    let mut bytes = 0_usize;
    let mut add = |size: usize| -> Result<(), Failure> {
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(())
    };
    for (_, observed) in &snapshot.reservations {
        if let Observed::Present {
            value: crate::decision::ReservationFact::Terminal(terminal),
            ..
        } = observed
        {
            match &terminal.kind {
                crate::decision::ReservationTerminalKind::Committed { refs, .. } => {
                    for value in refs {
                        add(value.name.0.len())?;
                    }
                }
                crate::decision::ReservationTerminalKind::Aborted { detail, .. } => {
                    add(detail.len())?;
                }
                crate::decision::ReservationTerminalKind::Expired
                | crate::decision::ReservationTerminalKind::StorageChanged { .. } => {}
            }
        }
    }
    Ok(bytes)
}

fn unambiguous(request: &RefWriteRequest<'_>, snapshot: &Snapshot) -> Result<(), Failure> {
    // Repeated identities are invalid even when their values happen to agree.
    if let Some(Observed::Present { value, .. }) = &snapshot.policy
        && value
            .allowed_signers
            .iter()
            .enumerate()
            .any(|(i, signer)| value.allowed_signers[..i].contains(signer))
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.denial {
        for ids in [&value.objects, &value.packs, &value.held] {
            if ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id)) {
                return Err(failure(FailureCode::InvalidResponse));
            }
        }
    }
    if let Some(Observed::Present { value, .. }) = &snapshot.admission
        && value.presence.iter().enumerate().any(|(i, change)| {
            value.presence[..i]
                .iter()
                .any(|other| other.name == change.name)
        })
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    for (i, (name, _)) in snapshot.refs.iter().enumerate() {
        if snapshot.refs[..i].iter().any(|(other, _)| other == name) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for (i, member) in snapshot.members.iter().enumerate() {
        if snapshot.members[..i]
            .iter()
            .any(|other| other.object == member.object)
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if let Observed::Present { value, .. } = &member.observed
            && (value.repository != request.repository || value.object != member.object)
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for (i, (id, _)) in snapshot.tickets.iter().enumerate() {
        if snapshot.tickets[..i].iter().any(|(other, _)| other == id) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for (i, (id, _)) in snapshot.reservations.iter().enumerate() {
        if snapshot.reservations[..i]
            .iter()
            .any(|(other, _)| other == id)
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for (i, object) in request.required.members.iter().enumerate() {
        if request.required.members[..i].contains(object) {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    for (i, proof) in request.ancestry.iter().enumerate() {
        if proof.repository != request.repository
            || request.ancestry[..i].iter().any(|other| {
                other.name == proof.name && other.from == proof.from && other.to == proof.to
            })
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
    }
    {
        for (i, change) in request.admitted.iter().enumerate() {
            if request.admitted[..i]
                .iter()
                .any(|other| other.name == change.name)
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
        }
    }
    if let Some((name, _)) = &request.presence
        && !request.changes.iter().any(|change| change.name == *name)
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    Ok(())
}

/// A present observation must carry the scope key its guard names; an absence
/// carries none, so the guard's own key is the only scope it can state.
fn keyed<T>(expected: &Observed<T>, scope_ok: impl FnOnce(&T) -> bool) -> bool {
    match expected {
        Observed::Present { value, .. } => scope_ok(value),
        Observed::Absent(_) => true,
    }
}

pub(super) fn matches(guard: &RequiredGuard, current: &Snapshot, now_ms: u64) -> bool {
    match guard {
        RequiredGuard::RefValue {
            repository,
            name,
            expected,
        } => {
            *repository == current.repository
                && current
                    .refs
                    .iter()
                    .any(|(key, value)| key == name && value == expected)
        }
        RequiredGuard::RefPresence {
            repository,
            name,
            present,
        } => {
            *repository == current.repository
                && current.refs.iter().any(|(key, value)| {
                    key == name && matches!(value, Observed::Present { .. }) == *present
                })
        }
        RequiredGuard::Replay { scope, expected } => {
            keyed(expected, |fact| fact.scope == *scope)
                && current.replay.as_ref() == Some(expected)
        }
        RequiredGuard::Ticket { id, expected } => current
            .tickets
            .iter()
            .any(|(key, value)| key == id && value == expected),
        RequiredGuard::Reservation { id, expected } => current
            .reservations
            .iter()
            .any(|(key, value)| key == id && value == expected),
        RequiredGuard::Authority {
            namespace,
            expected,
        } => {
            keyed(expected, |fact| fact.namespace == *namespace)
                && current.authority.as_ref() == Some(expected)
        }
        RequiredGuard::Grant {
            namespace,
            expected,
        } => {
            keyed(expected, |fact| fact.namespace == *namespace)
                && current.grant.as_ref() == Some(expected)
        }
        RequiredGuard::Repository { id, expected } => {
            *id == current.repository && current.lifecycle.as_ref() == Some(expected)
        }
        RequiredGuard::Membership {
            repository,
            object,
            expected,
        } => {
            *repository == current.repository
                && current
                    .members
                    .iter()
                    .any(|member| member.object == *object && member.observed == *expected)
        }
        RequiredGuard::Denial {
            repository,
            expected,
        } => *repository == current.repository && current.denial.as_ref() == Some(expected),
        RequiredGuard::Policy {
            repository,
            expected,
        } => *repository == current.repository && current.policy.as_ref() == Some(expected),
        RequiredGuard::Admission {
            operation,
            expected,
        } => {
            keyed(expected, |fact| fact.operation == *operation)
                && current.admission.as_ref() == Some(expected)
        }
        RequiredGuard::Accounting {
            repository,
            expected,
        } => *repository == current.repository && current.accounting.as_ref() == Some(expected),
        RequiredGuard::Storage {
            repository,
            expected,
        } => *repository == current.repository && current.storage.as_ref() == Some(expected),
        RequiredGuard::Publication {
            repository,
            expected,
        } => *repository == current.repository && current.publication.as_ref() == Some(expected),
        RequiredGuard::ValidThrough { instant_ms } => now_ms <= *instant_ms,
    }
}

// Conformance comparison must fail closed on contradictory acquired views too.
pub(super) fn ambiguous(current: &Snapshot) -> bool {
    current
        .refs
        .iter()
        .enumerate()
        .any(|(i, (key, _))| current.refs[..i].iter().any(|(other, _)| other == key))
        || current.members.iter().enumerate().any(|(i, member)| {
            current.members[..i]
                .iter()
                .any(|other| other.object == member.object)
        })
        || current
            .tickets
            .iter()
            .enumerate()
            .any(|(i, (key, _))| current.tickets[..i].iter().any(|(other, _)| other == key))
        || current
            .reservations
            .iter()
            .enumerate()
            .any(|(i, (key, _))| {
                current.reservations[..i]
                    .iter()
                    .any(|(other, _)| other == key)
            })
}
