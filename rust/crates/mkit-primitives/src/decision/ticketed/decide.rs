use super::{
    MAX_TICKETS_PER_ADVANCE, PendingBinding, StorageAccounting, TicketClaim,
    TicketedAdvanceRequest, UploadProof, VerificationVerdict,
};
use crate::{
    decision::{
        AcceptanceEffects, DurableOutcome, Guarded, MembershipEffect, Observed, OperationId,
        PermanentCode, PermanentRefusal, RefName, RefValue, RequiredGuard, ReservationAbortReason,
        ReservationAccounting, ReservationFact, ReservationId, ReservationOutcome,
        ReservationTerminal, ReservationTerminalKind, RetryReason, Snapshot, StorageEffect,
        StorageFact, TicketFact, TicketId, TicketTransition, WriteDecision,
        ref_write::{
            RefDecisionLimits, RefWriteKind, RefWriteRequest,
            checks::{bounds, failure},
            decide::{Attempt, push_guard},
        },
    },
    error::{Failure, FailureCode},
    evidence::RepositoryId,
};

const INVALID_TICKET: &str = "invalid or expired upload ticket";
const INCOMPLETE_UPLOAD: &str = "upload not complete for ticket";
const SIGNER_MISMATCH: &str = "upload ticket binding mismatch";
const EPOCH_MOVED: &str = "namespace authority generation changed";

/// Decide one ticketed advance with every read guard sealed.
///
/// The host acquires the ticket, reservation, storage, and replay
/// observations named by the request before invoking this function;
/// unacquired facts are `UnavailableInput`, never inferred absence.
/// Decision order matches the reference planner: pending-reservation
/// stability, replay, ticket rows and upload proofs in request order,
/// verification, context fences, ticket authority generations, then the
/// ref changes. Ticket consumption, reservation settlement, membership,
/// storage counting and replay all commit in the same atomic unit.
///
/// # Errors
/// `InvalidRefRequest` for a shape the wire rejects, `UnavailableInput` for
/// unacquired facts, `InvalidResponse` for wrongly scoped or contradictory
/// observations, `ResourceLimit` for the explicit finite ceilings.
pub fn decide_ticketed_advance(
    request: &TicketedAdvanceRequest<'_>,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<Guarded<WriteDecision>, Failure> {
    let write = &request.write;
    if write.kind != RefWriteKind::Advance || write.changes.len() != 2 {
        return Err(failure(FailureCode::InvalidRefRequest));
    }
    validate_claims(request.tickets)?;
    if !request.tickets.is_empty() {
        if write.changes.iter().any(|change| change.target.is_none())
            || !canonical_pair(&write.changes[0].name, &write.changes[1].name)
        {
            return Err(failure(FailureCode::InvalidRefRequest));
        }
        if write.signer.is_none() || write.operation.is_none() {
            return Err(failure(FailureCode::InvalidRefRequest));
        }
    }
    // A basis for another repository is a host error on every path, including
    // those that answer from a recorded result or a ticket refusal first.
    if let VerificationVerdict::Verified(bases) = &request.verification
        && (bases.is_empty() || bases.iter().any(|b| b.repository() != write.repository))
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    bounds(write, snapshot, limits)?;
    let mut attempt = Attempt::new(write, snapshot, limits)?;
    let decision = drive(request, &mut attempt, snapshot)?;
    Ok(seal(attempt, write.repository, decision))
}

fn drive(
    request: &TicketedAdvanceRequest<'_>,
    attempt: &mut Attempt<'_>,
    snapshot: &Snapshot,
) -> Result<WriteDecision, Failure> {
    let write = &request.write;
    // The admission reservation's exact admission-written state fences the
    // whole decision before replay or tickets are considered.
    if let Some(pending) = &request.pending {
        let observed = observed_reservation(snapshot, &pending.reservation)?;
        attempt.add(RequiredGuard::Reservation {
            id: pending.reservation.clone(),
            expected: observed.clone(),
        })?;
        if !matches!(
            &pending.expected,
            Observed::Present {
                value: ReservationFact::Pending { .. },
                ..
            }
        ) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if observed != &pending.expected {
            return Ok(WriteDecision::Retry(RetryReason::Unavailable));
        }
    }
    // A recorded replay answers before ticket validation; a pending
    // reservation turns it into an in-flight retry.
    if let Some(recorded) = attempt.replay()? {
        return Ok(match recorded {
            WriteDecision::ReturnRecorded(_) if request.pending.is_some() => {
                WriteDecision::Retry(RetryReason::InFlight)
            }
            other => other,
        });
    }
    // Ticket rows in request order; the first failure decides.
    let mut valid = Vec::new();
    valid
        .try_reserve(request.tickets.len())
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    for claim in request.tickets {
        let observed = observed_ticket(snapshot, &claim.ticket)?;
        let verdict = match validate(claim, observed, write)? {
            Verdict::Valid(_) if claim.proof != UploadProof::Ready => {
                Verdict::Refuse(PermanentCode::FailedPrecondition, INCOMPLETE_UPLOAD)
            }
            other => other,
        };
        // Every row the decision examined is a read dependency, whatever the
        // verdict: a refusal, conflict or replay built on these rows commits
        // only while they are unchanged.
        attempt.add(RequiredGuard::Ticket {
            id: claim.ticket.clone(),
            expected: observed.clone(),
        })?;
        match verdict {
            Verdict::Valid(fact) => valid.push((claim, fact, observed)),
            Verdict::Refuse(code, message) => return attempt.reject(code, message),
        }
    }
    if let Some(decision) = verification(request, attempt, &valid)? {
        return Ok(decision);
    }
    if let Some(decision) = attempt.context()? {
        return Ok(decision);
    }
    // Tickets issued under a superseded authority generation cannot commit.
    // The generation is the guarded authority binding's, so the Authority guard
    // that `context` collected already covers it.
    if let Some(bound) = &write.required.authority
        && valid
            .iter()
            .any(|(_, fact, _)| fact.authority_generation != Some(bound.generation))
    {
        return attempt.reject(PermanentCode::PermissionDenied, EPOCH_MOVED);
    }
    let decision = attempt.refs()?;
    match decision {
        WriteDecision::Apply(mut effects) => {
            augment_apply(request, attempt, snapshot, &valid, &mut effects)?;
            Ok(WriteDecision::Apply(effects))
        }
        WriteDecision::Conflict {
            current,
            replay,
            reservation: None,
        } => Ok(WriteDecision::Conflict {
            current,
            replay,
            reservation: request
                .pending
                .as_ref()
                .map(|pending| pending_outcome(request, pending, true)),
        }),
        other => Ok(other),
    }
}

#[allow(clippy::too_many_lines)] // One apply pass interleaves ticket, reservation, and storage effects in physical order.
fn augment_apply(
    request: &TicketedAdvanceRequest<'_>,
    attempt: &mut Attempt<'_>,
    snapshot: &Snapshot,
    valid: &[(&TicketClaim, &TicketFact, &Observed<TicketFact>)],
    effects: &mut AcceptanceEffects,
) -> Result<(), Failure> {
    let write = &request.write;
    let operation = write
        .operation
        .clone()
        .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
    let outcome_refs: Vec<RefValue> = effects
        .refs
        .iter()
        .map(|effect| RefValue {
            name: effect.name.clone(),
            value: effect.target,
        })
        .collect();
    for &(claim, fact, observed) in valid {
        let res_observed = observed_reservation(snapshot, &fact.reservation)?;
        if !matches!(
            res_observed,
            Observed::Present {
                value: ReservationFact::Ticketed(id),
                ..
            } if id == &claim.ticket
        ) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        attempt.add(RequiredGuard::Ticket {
            id: claim.ticket.clone(),
            expected: observed.clone(),
        })?;
        attempt.add(RequiredGuard::Reservation {
            id: fact.reservation.clone(),
            expected: res_observed.clone(),
        })?;
        effects.tickets.push(TicketTransition {
            id: claim.ticket.clone(),
            next: None,
        });
        // The consumed pack joins the repository's membership. A pack named by
        // several tickets is added once. Cross-partition relays remain host
        // lowering of this semantic addition.
        if !effects
            .membership
            .iter()
            .any(|added| added.pack.id == fact.pack.id)
        {
            effects.membership.push(MembershipEffect {
                repository: write.repository,
                pack: fact.pack,
            });
        }
        let terminal = ReservationTerminal {
            repository: write.repository,
            occurred_ms: write.now_ms,
            kind: ReservationTerminalKind::Committed {
                refs: outcome_refs.clone(),
                accounting: ReservationAccounting {
                    bytes_stored: fact.pack.len,
                    new_to_repository: if claim.counted { 0 } else { fact.pack.len },
                    new_to_store: fact.pack.len,
                },
            },
        };
        effects.reservations.push(ReservationOutcome {
            id: fact.reservation.clone(),
            terminal: terminal.clone(),
        });
        effects.outcomes.push(DurableOutcome {
            operation: operation.clone(),
            reservation: fact.reservation.clone(),
            terminal,
        });
    }
    if let StorageAccounting::Inline {
        observed,
        outcome,
        occurred_ms,
    } = &request.storage
    {
        let mut added = 0_u64;
        let mut fresh = std::collections::BTreeSet::new();
        for &(claim, fact, _) in valid {
            if !claim.counted && fresh.insert(fact.pack.id) {
                added = added
                    .checked_add(fact.pack.len)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
            }
        }
        if !valid.is_empty() {
            // `counted` is the marker observation of each claim's pack. A marker
            // appears only in a batch that also moves this counter, so the exact
            // counter row guards every claim's `counted` value, whether or not
            // this batch adds bytes.
            let acquired = snapshot
                .storage
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            if acquired != observed {
                return Err(failure(FailureCode::InvalidResponse));
            }
            attempt.add(RequiredGuard::Storage {
                repository: write.repository,
                expected: acquired.clone(),
            })?;
        }
        if added > 0 {
            let Observed::Present { value: counter, .. } = observed else {
                return Err(failure(FailureCode::InvalidResponse));
            };
            let next = StorageFact {
                stored_bytes: counter
                    .stored_bytes
                    .checked_add(added)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
                version: counter
                    .version
                    .checked_add(1)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
            };
            let counter_row = observed_reservation(snapshot, outcome)?;
            // The counter-change outcome id derives from the next counter
            // version, so a live row there contradicts the counter itself.
            if !matches!(counter_row, Observed::Absent(_)) {
                return Err(failure(FailureCode::InvalidResponse));
            }
            attempt.add(RequiredGuard::Reservation {
                id: outcome.clone(),
                expected: counter_row.clone(),
            })?;
            effects.storage.push(StorageEffect {
                repository: write.repository,
                next,
            });
            // The counter change is also a terminal row at its outcome id,
            // settled and delivered like a reservation outcome.
            let terminal = ReservationTerminal {
                repository: write.repository,
                occurred_ms: *occurred_ms,
                kind: ReservationTerminalKind::StorageChanged {
                    stored_bytes: next.stored_bytes,
                    version: next.version,
                },
            };
            effects.reservations.push(ReservationOutcome {
                id: outcome.clone(),
                terminal: terminal.clone(),
            });
            effects.outcomes.push(DurableOutcome {
                operation: operation.clone(),
                reservation: outcome.clone(),
                terminal,
            });
        }
    }
    if let Some(pending) = &request.pending {
        let terminal = pending_terminal(request, pending, false);
        effects.reservations.push(ReservationOutcome {
            id: pending.reservation.clone(),
            terminal: terminal.clone(),
        });
        effects.outcomes.push(DurableOutcome {
            operation,
            reservation: pending.reservation.clone(),
            terminal,
        });
    }
    Ok(())
}

/// The pending reservation's terminal payload: `Committed` records the wire
/// refs on success, `Aborted` with an empty detail on a ref conflict.
fn pending_terminal(
    request: &TicketedAdvanceRequest<'_>,
    pending: &PendingBinding,
    conflict: bool,
) -> ReservationTerminal {
    let write = &request.write;
    let repository = match &pending.expected {
        Observed::Present {
            value: ReservationFact::Pending { repository, .. },
            ..
        } => *repository,
        _ => write.repository,
    };
    ReservationTerminal {
        repository,
        occurred_ms: pending.occurred_ms,
        kind: if conflict {
            ReservationTerminalKind::Aborted {
                reason: ReservationAbortReason::RefConflict,
                detail: String::new(),
            }
        } else {
            ReservationTerminalKind::Committed {
                refs: write
                    .changes
                    .iter()
                    .map(|change| RefValue {
                        name: change.name.clone(),
                        value: change.target,
                    })
                    .collect(),
                accounting: ReservationAccounting {
                    bytes_stored: 0,
                    new_to_repository: 0,
                    new_to_store: 0,
                },
            }
        },
    }
}

fn pending_outcome(
    request: &TicketedAdvanceRequest<'_>,
    pending: &PendingBinding,
    conflict: bool,
) -> ReservationOutcome {
    ReservationOutcome {
        id: pending.reservation.clone(),
        terminal: pending_terminal(request, pending, conflict),
    }
}

/// Decide the separate defensive abort for tickets whose pack is missing.
///
/// The request's verification verdict is not consulted: cleanup settles only
/// ticket and reservation rows and never accepts a pack.
///
/// This is its own atomic unit, never coupled to the failed ref write: it
/// reproduces the reference's first-failure rule, aborts only valid tickets
/// with `PackMissing` proofs at or before the first failure, and commits only
/// ticket closes and `Aborted`/`PackMissing` settlements. An empty effect set
/// means no ticket qualified; the host returns the first failure as before.
///
/// # Errors
/// Same classes as [`decide_ticketed_advance`]; `InvalidResponse` when no
/// ticket fails (the host decides cleanup only on a failure).
#[allow(clippy::too_many_lines)] // One cleanup decision walks every lost ticket with its reservation terminal.
pub fn decide_ticket_cleanup(
    request: &TicketedAdvanceRequest<'_>,
    detail: &str,
    occurred_ms: u64,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<Guarded<WriteDecision>, Failure> {
    let write = &request.write;
    if write.kind != RefWriteKind::Advance
        || write.changes.len() != 2
        || write.signer.is_none()
        || write.operation.is_none()
    {
        return Err(failure(FailureCode::InvalidRefRequest));
    }
    validate_claims(request.tickets)?;
    bounds(write, snapshot, limits)?;
    if detail.len() > limits.public_message_bytes as usize {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut guards = Vec::new();
    guards
        .try_reserve_exact(limits.guards.min(64) as usize)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    let mut first_failure = None;
    let mut rows = Vec::new();
    rows.try_reserve(request.tickets.len())
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    for (i, claim) in request.tickets.iter().enumerate() {
        let observed = observed_ticket(snapshot, &claim.ticket)?;
        match validate(claim, observed, write)? {
            Verdict::Valid(fact) => {
                if claim.proof != UploadProof::Ready && first_failure.is_none() {
                    first_failure = Some(i);
                }
                rows.push(Some((claim, fact, observed)));
            }
            Verdict::Refuse(..) => {
                rows.push(None);
                if first_failure.is_none() {
                    first_failure = Some(i);
                }
            }
        }
    }
    let Some(boundary) = first_failure else {
        return Err(failure(FailureCode::InvalidResponse));
    };
    let operation = write
        .operation
        .clone()
        .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
    let mut effects = AcceptanceEffects {
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
    // The abort set depends on every ticket row up to the first failure, not
    // only on the rows it aborts, so each examined row is a read dependency.
    for (claim, observed) in request.tickets[..=boundary]
        .iter()
        .map(|claim| (claim, observed_ticket(snapshot, &claim.ticket)))
    {
        push_guard(
            &mut guards,
            limits.guards,
            RequiredGuard::Ticket {
                id: claim.ticket.clone(),
                expected: observed?.clone(),
            },
        )?;
    }
    for &(claim, fact, _) in rows[..=boundary].iter().flatten() {
        if claim.proof != UploadProof::PackMissing {
            continue;
        }
        let res_observed = observed_reservation(snapshot, &fact.reservation)?;
        // Only the reservation this ticket is bound to may be aborted; any
        // other state is already settled, and a second terminal is forbidden.
        if !matches!(
            res_observed,
            Observed::Present {
                value: ReservationFact::Ticketed(id),
                ..
            } if id == &claim.ticket
        ) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        push_guard(
            &mut guards,
            limits.guards,
            RequiredGuard::Reservation {
                id: fact.reservation.clone(),
                expected: res_observed.clone(),
            },
        )?;
        effects.tickets.push(TicketTransition {
            id: claim.ticket.clone(),
            next: None,
        });
        let terminal = ReservationTerminal {
            repository: write.repository,
            occurred_ms,
            kind: ReservationTerminalKind::Aborted {
                reason: ReservationAbortReason::PackMissing,
                detail: detail.to_owned(),
            },
        };
        effects.reservations.push(ReservationOutcome {
            id: fact.reservation.clone(),
            terminal: terminal.clone(),
        });
        effects.outcomes.push(DurableOutcome {
            operation: operation.clone(),
            reservation: fact.reservation.clone(),
            terminal,
        });
    }
    Ok(Guarded {
        repository: write.repository,
        decision: WriteDecision::Apply(effects),
        required: guards,
        source_fences: Vec::new(),
    })
}

/// Decide a standalone reservation settlement.
///
/// `expected` is the host's asserted prior: `Present` of `Pending` or
/// `Ticketed` for a guarded transition, `Absent` for a direct abort with no
/// prior row. When the fresh observation differs, another contender settled
/// the reservation and the decision applies no effects. Legal transitions:
/// `Pending` or `Ticketed` settle to `Committed`, `Aborted` or (`Ticketed`
/// only) `Expired`; `Absent` only creates `Aborted`.
///
/// # Errors
/// `UnavailableInput` for an unacquired reservation observation,
/// `InvalidResponse` for an illegal transition or a terminal bound to a
/// different repository, `ResourceLimit` for an overlong abort detail.
pub fn decide_reservation_settlement(
    repository: RepositoryId,
    operation: &OperationId,
    reservation: &ReservationId,
    expected: &Observed<ReservationFact>,
    terminal: &ReservationTerminal,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<Guarded<WriteDecision>, Failure> {
    if snapshot.repository != repository || terminal.repository != repository {
        return Err(failure(FailureCode::InvalidResponse));
    }
    settlement_bounds(repository, expected, terminal, snapshot, limits)?;
    let prior_legal = match expected {
        Observed::Present {
            value: ReservationFact::Pending { .. } | ReservationFact::Ticketed(_),
            ..
        } => true,
        Observed::Absent(_) => matches!(terminal.kind, ReservationTerminalKind::Aborted { .. }),
        _ => false,
    };
    let legal = prior_legal
        && matches!(
            (&expected, &terminal.kind),
            (
                Observed::Present {
                    value: ReservationFact::Pending { .. },
                    ..
                },
                ReservationTerminalKind::Committed { .. } | ReservationTerminalKind::Aborted { .. },
            ) | (
                Observed::Present {
                    value: ReservationFact::Ticketed(_),
                    ..
                },
                ReservationTerminalKind::Committed { .. }
                    | ReservationTerminalKind::Aborted { .. }
                    | ReservationTerminalKind::Expired,
            ) | (Observed::Absent(_), ReservationTerminalKind::Aborted { .. })
        );
    if !legal {
        return Err(failure(FailureCode::InvalidResponse));
    }
    if let ReservationTerminalKind::Aborted { detail, .. } = &terminal.kind
        && detail.len() > limits.public_message_bytes as usize
    {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let observed = observed_reservation(snapshot, reservation)?;
    let mut effects = AcceptanceEffects {
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
    if observed == expected {
        effects
            .reservations
            .try_reserve_exact(1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        effects
            .outcomes
            .try_reserve_exact(1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        effects.reservations.push(ReservationOutcome {
            id: reservation.clone(),
            terminal: copy_terminal(terminal)?,
        });
        effects.outcomes.push(DurableOutcome {
            operation: operation.clone(),
            reservation: reservation.clone(),
            terminal: copy_terminal(terminal)?,
        });
    }
    let mut required = Vec::new();
    required
        .try_reserve_exact(2)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    let guarded_row = match observed {
        Observed::Present {
            value: ReservationFact::Terminal(value),
            revision,
        } => Observed::Present {
            value: ReservationFact::Terminal(copy_terminal(value)?),
            revision: *revision,
        },
        other => other.clone(),
    };
    required.push(RequiredGuard::Reservation {
        id: reservation.clone(),
        expected: guarded_row,
    });
    if observed == expected {
        close_settled_ticket(observed, reservation, snapshot, &mut required, &mut effects)?;
    }
    Ok(Guarded {
        repository,
        decision: WriteDecision::Apply(effects),
        required,
        source_fences: Vec::new(),
    })
}

/// A `Ticketed` reservation ends together with its ticket: settling it alone
/// would leave a live ticket whose consumption writes a second terminal
/// outcome. The same effects close the ticket row, and its exact observation
/// (the row, or its absence) is guarded so no other path can race it.
fn close_settled_ticket(
    settled: &Observed<ReservationFact>,
    reservation: &ReservationId,
    snapshot: &Snapshot,
    required: &mut Vec<RequiredGuard>,
    effects: &mut AcceptanceEffects,
) -> Result<(), Failure> {
    let Observed::Present {
        value: ReservationFact::Ticketed(ticket),
        ..
    } = settled
    else {
        return Ok(());
    };
    let row = observed_ticket(snapshot, ticket)?;
    if let Observed::Present { value, .. } = row
        && (value.ticket != *ticket || value.reservation != *reservation)
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    required.push(RequiredGuard::Ticket {
        id: ticket.clone(),
        expected: row.clone(),
    });
    if matches!(row, Observed::Present { .. }) {
        effects
            .tickets
            .try_reserve_exact(1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        effects.tickets.push(TicketTransition {
            id: ticket.clone(),
            next: None,
        });
    }
    Ok(())
}

enum Verdict<'a> {
    Valid(&'a TicketFact),
    Refuse(PermanentCode, &'static str),
}

/// Validate one claimed ticket's row against its acquired observation: exact
/// identity, destination binding, expiry, and signer. The caller decides the
/// upload proof separately so a row-valid ticket with a missing pack stays
/// visible to the cleanup decision.
fn validate<'a>(
    claim: &TicketClaim,
    observed: &'a Observed<TicketFact>,
    write: &RefWriteRequest<'_>,
) -> Result<Verdict<'a>, Failure> {
    let Observed::Present { value: fact, .. } = observed else {
        return Ok(Verdict::Refuse(
            PermanentCode::FailedPrecondition,
            INVALID_TICKET,
        ));
    };
    if fact.ticket != claim.ticket {
        return Err(failure(FailureCode::InvalidResponse));
    }
    if fact.repository != write.repository
        || fact.name != write.changes[1].name
        || fact.expires_ms <= write.now_ms
    {
        return Ok(Verdict::Refuse(
            PermanentCode::FailedPrecondition,
            INVALID_TICKET,
        ));
    }
    if Some(fact.signer) != write.signer {
        return Ok(Verdict::Refuse(
            PermanentCode::PermissionDenied,
            SIGNER_MISMATCH,
        ));
    }
    Ok(Verdict::Valid(fact))
}

fn observed_ticket<'a>(
    snapshot: &'a Snapshot,
    id: &TicketId,
) -> Result<&'a Observed<TicketFact>, Failure> {
    snapshot
        .tickets
        .iter()
        .find(|(key, _)| key == id)
        .map(|(_, observed)| observed)
        .ok_or_else(|| failure(FailureCode::UnavailableInput))
}

fn observed_reservation<'a>(
    snapshot: &'a Snapshot,
    id: &ReservationId,
) -> Result<&'a Observed<ReservationFact>, Failure> {
    snapshot
        .reservations
        .iter()
        .find(|(key, _)| key == id)
        .map(|(_, observed)| observed)
        .ok_or_else(|| failure(FailureCode::UnavailableInput))
}

/// Canonical `refs/mkit/packmap/<x>`/`refs/heads/<x>` pairing.
fn canonical_pair(packmap: &RefName, head: &RefName) -> bool {
    let branch = head.0.strip_prefix("refs/heads/");
    branch.is_some() && branch == packmap.0.strip_prefix("refs/mkit/packmap/")
}

fn seal(
    attempt: Attempt<'_>,
    repository: crate::evidence::RepositoryId,
    decision: WriteDecision,
) -> Guarded<WriteDecision> {
    let source_fences = if matches!(decision, WriteDecision::ReturnRecorded(_)) {
        Vec::new()
    } else {
        attempt
            .req
            .required
            .source
            .into_iter()
            .map(|fence| crate::decision::RequiredSourceFence::Published(Box::new(fence.clone())))
            .collect()
    };
    Guarded {
        repository,
        decision,
        required: attempt.guards,
        source_fences,
    }
}

fn validate_claims(claims: &[TicketClaim]) -> Result<(), Failure> {
    if claims.len() > MAX_TICKETS_PER_ADVANCE
        || claims
            .iter()
            .enumerate()
            .any(|(i, claim)| claims[..i].iter().any(|prior| prior.ticket == claim.ticket))
    {
        return Err(failure(FailureCode::InvalidRefRequest));
    }
    Ok(())
}

// Keep the reference's reservation::abort_reason classification, including its
// safe-detail rule. Content errors such as invalid_argument settle as Internal;
// policy/precondition refusals carry a bounded, printable denial detail.
fn verification(
    request: &TicketedAdvanceRequest<'_>,
    attempt: &mut Attempt<'_>,
    valid: &[(&TicketClaim, &TicketFact, &Observed<TicketFact>)],
) -> Result<Option<WriteDecision>, Failure> {
    let limits = attempt.limits;
    Ok(match &request.verification {
        VerificationVerdict::Pending => Some(WriteDecision::Retry(RetryReason::Unavailable)),
        VerificationVerdict::Refused(refusal) => {
            if refusal.public_message.len() > limits.public_message_bytes as usize {
                return Err(failure(FailureCode::ResourceLimit));
            }
            Some(WriteDecision::Reject {
                refusal: refusal.clone(),
                terminal: None,
                reservation: request
                    .pending
                    .as_ref()
                    .map(|pending| failed_proof_outcome(request, pending, refusal)),
            })
        }
        VerificationVerdict::Verified(bases) => {
            // The verified packs are the packs being accepted: a basis for one
            // pack never accepts another pack's ticket.
            if valid.iter().any(|(_, fact, _)| {
                !bases
                    .iter()
                    .any(|basis| basis.covers(&fact.pack.id, fact.pack.len))
            }) {
                return Err(failure(FailureCode::InvalidResponse));
            }
            // Everything acceptance relied on becomes a guard of this decision;
            // the repository was checked on entry.
            for basis in *bases {
                for guard in basis.guards() {
                    attempt.add(guard.clone())?;
                }
            }
            None
        }
    })
}

fn failed_proof_outcome(
    request: &TicketedAdvanceRequest<'_>,
    pending: &PendingBinding,
    refusal: &PermanentRefusal,
) -> ReservationOutcome {
    let (reason, detail) = proof_abort(refusal);
    let mut terminal = pending_terminal(request, pending, false);
    terminal.kind = ReservationTerminalKind::Aborted { reason, detail };
    ReservationOutcome {
        id: pending.reservation.clone(),
        terminal,
    }
}

fn proof_abort(refusal: &PermanentRefusal) -> (ReservationAbortReason, String) {
    if matches!(
        refusal.code,
        PermanentCode::PermissionDenied | PermanentCode::FailedPrecondition
    ) {
        let detail = if refusal.public_message.len() <= 512
            && !refusal.public_message.chars().any(char::is_control)
        {
            refusal.public_message.clone()
        } else {
            "write denied".into()
        };
        (ReservationAbortReason::Unspecified, detail)
    } else {
        (ReservationAbortReason::Internal, String::new())
    }
}

fn settlement_bounds(
    repository: RepositoryId,
    expected: &Observed<ReservationFact>,
    terminal: &ReservationTerminal,
    snapshot: &Snapshot,
    mut limits: RefDecisionLimits,
) -> Result<(), Failure> {
    use crate::decision::ref_write::{MembershipWindow, RefRequirements};
    if limits.guards == 0 {
        return Err(failure(FailureCode::ResourceLimit));
    }
    // Charge the independently supplied prior and terminal, including the two
    // output copies, before validating or cloning any variable-size contents.
    let mut refs = 0_u32;
    let mut bytes = 0_u64;
    let mut charge = |value: &ReservationTerminal| -> Result<(), Failure> {
        match &value.kind {
            ReservationTerminalKind::Committed { refs: values, .. } => {
                refs = refs
                    .checked_add(
                        u32::try_from(values.len())
                            .map_err(|_| failure(FailureCode::ResourceLimit))?,
                    )
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
                if refs > limits.facts {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                for value in values {
                    bytes = bytes
                        .checked_add(value.name.0.len() as u64)
                        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
                    if bytes > limits.bytes {
                        return Err(failure(FailureCode::ResourceLimit));
                    }
                }
            }
            ReservationTerminalKind::Aborted { detail, .. } => {
                if detail.len() > limits.public_message_bytes as usize {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                bytes = bytes
                    .checked_add(detail.len() as u64)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
            }
            _ => {}
        }
        Ok(())
    };
    charge(terminal)?;
    if let Observed::Present {
        value: ReservationFact::Terminal(value),
        ..
    } = expected
    {
        charge(value)?;
    }
    limits.facts = limits
        .facts
        .checked_sub(
            refs.checked_add(2)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        )
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    limits.bytes = limits
        .bytes
        .checked_sub(
            bytes
                .checked_mul(3)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        )
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    limits.work = limits
        .work
        .checked_sub(
            bytes
                .saturating_mul(3)
                .saturating_add(u64::from(refs) * 8 + 64),
        )
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    let request = RefWriteRequest {
        repository,
        operation: None,
        kind: RefWriteKind::Update,
        changes: &[],
        admitted: &[],
        presence: None,
        signer: None,
        replay: None,
        ancestry: &[],
        now_ms: 0,
        required: RefRequirements {
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
        },
    };
    bounds(&request, snapshot, limits)
}

fn copy_terminal(value: &ReservationTerminal) -> Result<ReservationTerminal, Failure> {
    let copy_string = |value: &str| -> Result<String, Failure> {
        let mut copied = String::new();
        copied
            .try_reserve_exact(value.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        copied.push_str(value);
        Ok(copied)
    };
    let kind = match &value.kind {
        ReservationTerminalKind::Committed { refs, accounting } => {
            let mut copied = Vec::new();
            copied
                .try_reserve_exact(refs.len())
                .map_err(|_| failure(FailureCode::ResourceLimit))?;
            for item in refs {
                copied.push(RefValue {
                    name: RefName(copy_string(&item.name.0)?),
                    value: item.value,
                });
            }
            ReservationTerminalKind::Committed {
                refs: copied,
                accounting: *accounting,
            }
        }
        ReservationTerminalKind::Aborted { reason, detail } => ReservationTerminalKind::Aborted {
            reason: *reason,
            detail: copy_string(detail)?,
        },
        other => other.clone(),
    };
    Ok(ReservationTerminal {
        repository: value.repository,
        occurred_ms: value.occurred_ms,
        kind,
    })
}
