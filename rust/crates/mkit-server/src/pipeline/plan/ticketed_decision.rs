//! Composed ticketed-advance decision (SPEC-SERVER §6.3, §9.3–§9.5).
//!
//! One portable decision covers pending stability, replay, ticket rows,
//! ticket authority generations and the ref pair. The physical emission
//! order is preserved by lowering through the same store emitters
//! (`tickets::plan_ticket_close`, `OutboxBuilder::outcome`,
//! `repo_storage::plan_count`, `tickets::plan_membership`) the reference
//! planner used: this adapter introduces no store read of its own — it
//! decodes only acquired rows — and proves every sealed guard against the
//! emitted preconditions.
//!
//! Shapes outside the portable contract — an upstream admission rejection the
//! batch only records, a fork-barriered request — keep the unextracted
//! planner's path entirely (SPEC-SERVER §3.1, "Reference-server behavior").

use mkit_core::hash::hash;
use mkit_primitives::{
    decision::{
        Guarded, Observed, OperationId, PermanentCode, PermanentRefusal, RefName, ReplayFact,
        ReplayScope, ReplayState, RequiredGuard, ReservationFact, ReservationId, ReservationOp,
        RetryReason, Snapshot as Facts, StorageFact, TerminalResult, TicketFact, TicketId,
        WriteDecision,
        ref_write::{
            AdmittedRef, MembershipWindow, RefChange, RefDecisionLimits, RefReplay,
            RefRequirements, RefWriteKind, RefWriteRequest, check_guard_completeness,
        },
        ticketed::{
            PendingBinding, StorageAccounting, TicketClaim, TicketedAdvanceRequest, UploadProof,
            decide_ticketed_advance,
        },
    },
    error::FailureCode,
    evidence::{PackSource, RepositoryId, Revision, SourceBinding},
};

use super::{PlanClock, Planned, Snapshot, WriteRequest, corrupt};
use crate::{
    error::ServerError,
    op::PresenceRequirement,
    pipeline::{internal, meta_error, ms},
    replay::StoredResult,
    store::codec::{self, ReservationV1, TicketV1},
    store::{Key, Precondition, Write, keys, repo_storage, tickets},
};

const EPOCH_MOVED: &str = "namespace authority generation changed";

/// The composed decision plus the decoded ticket rows the reference
/// consumption lowering replays.
pub(super) struct Decided {
    guarded: Box<Guarded<WriteDecision>>,
    /// Decoded valid ticket rows, request order — `plan_consumption`'s input.
    pub(super) tickets: Vec<TicketV1>,
    /// The stored result a committed replay record already carries.
    recorded: Option<StoredResult>,
    /// Semantic reservation id → its store key, for guard projection.
    reservation_keys: Vec<(ReservationId, Key)>,
}

impl Decided {
    /// The pending-stability/replay/ticket verdict the composed decision
    /// reached. `None` continues into the shared fragments; a held authority
    /// refusal reports at the generation-check position instead.
    pub(super) fn verdict(&self) -> Option<Result<Planned, ServerError>> {
        match self.guarded.decision() {
            WriteDecision::Retry(RetryReason::Unavailable) => Some(Err(ServerError::unavailable(
                "admission reservation changed; retry",
            ))),
            WriteDecision::Retry(_) => Some(Err(ServerError::aborted_retryable(
                "operation already in flight; retry",
            ))),
            WriteDecision::ReturnRecorded(_) => {
                let recorded = self
                    .recorded
                    .clone()
                    .ok_or_else(|| internal("missing recorded result"));
                Some(recorded.map(Planned::Done))
            }
            WriteDecision::Reject { refusal, .. } if refusal.public_message == EPOCH_MOVED => None,
            WriteDecision::Reject { refusal, .. } => Some(Err(refusal_error(refusal))),
            _ => None,
        }
    }

    /// Whether the composed decision refused on a superseded ticket authority
    /// generation; reported at the generation-check position.
    pub(super) fn epoch_moved(&self) -> bool {
        matches!(
            self.guarded.decision(),
            WriteDecision::Reject { refusal, .. } if refusal.public_message == EPOCH_MOVED
        )
    }
}

fn refusal_error(refusal: &PermanentRefusal) -> ServerError {
    match refusal.code {
        PermanentCode::PermissionDenied => {
            ServerError::permission_denied(refusal.public_message.clone())
        }
        PermanentCode::InvalidArgument => {
            ServerError::invalid_argument(refusal.public_message.clone())
        }
        PermanentCode::FailedPrecondition => {
            ServerError::failed_precondition(refusal.public_message.clone())
        }
        PermanentCode::NotFound => ServerError::not_found(refusal.public_message.clone()),
        _ => internal("unsupported ticketed refusal"),
    }
}

/// Decide the ticketed-advance fragment. `None` keeps the unextracted
/// planner: non-ticketed writes, and shapes the contract does not serve.
pub(super) fn decide(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
) -> Option<Decided> {
    // Decoding is speculative and has no effects. If a later row cannot be
    // projected, let the reference path examine its original prefix: a replay,
    // changed pending reservation or earlier refusal can precede that row.
    // This also preserves physical corruption diagnostics for unsupported facts.
    try_decide(req, snap, clock).ok().flatten()
}

#[allow(clippy::too_many_lines)] // One decode-and-decide pass builds every observation in snapshot order.
fn try_decide(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
) -> Result<Option<Decided>, ServerError> {
    let Some(advance) = req.advance.as_ref() else {
        return Ok(None);
    };
    // The wire's advance carries the packmap/head pair; an upstream rejection
    // only records a result, and a fork-barriered request keeps its check
    // before deciding — the contract serves none of these. Unsigned or
    // replayless advances keep the reference path: no durable outcome names
    // their operation.
    if req.refs.len() != 2 || req.rejection.is_some() || req.fork_barrier || req.replay.is_none() {
        return Ok(None);
    }
    // The canonical identity: the ticket row's repo field and the request's
    // repository both compare by this value, matching the reference's
    // `value.repo == advance.repo_id.name` name check.
    let repository = RepositoryId(hash(
        repo_storage::identity(&advance.repo_id.namespace, &advance.repo_id.name).as_bytes(),
    ));
    let now_ms = ms(clock.business_now_ms);
    let changes: Vec<_> = req
        .refs
        .iter()
        .map(|update| RefChange {
            name: RefName(update.name.clone()),
            condition: update.condition,
            target: update.new,
        })
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let admitted: Vec<_> = req
        .resolved_ref_updates
        .iter()
        .filter(|update| seen.insert(update.name.as_str()))
        .map(|update| AdmittedRef {
            name: RefName(update.name.clone()),
            target: update.new,
            prior_present: update.prior_present(),
        })
        .collect();
    let presence = req
        .grant
        .as_ref()
        .and_then(|grant| grant.presence_requirement.as_ref())
        .filter(|requirement| {
            let name = match requirement {
                PresenceRequirement::Absent(name) | PresenceRequirement::Present(name) => name,
            };
            req.refs.iter().any(|update| update.name == *name)
        })
        .map(|requirement| match requirement {
            PresenceRequirement::Absent(name) => (RefName(name.clone()), false),
            PresenceRequirement::Present(name) => (RefName(name.clone()), true),
        });
    let replay = req.replay.map(|replay| RefReplay {
        scope: ReplayScope(replay.scope),
        fingerprint: replay.fingerprint,
        expires_ms: ms(replay.expires_at_ms),
    });
    let write = RefWriteRequest {
        repository,
        operation: req.replay.map(|replay| OperationId(replay.scope)),
        kind: RefWriteKind::Advance,
        changes: &changes,
        admitted: &admitted,
        presence,
        signer: Some(advance.signer),
        replay,
        ancestry: &[],
        now_ms,
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

    // Decode every claimed ticket row once: it feeds the semantic
    // observation, the claim's `counted` flag, and the reference lowering.
    let mut facts = Facts {
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
        storage: None,
    };
    for update in req.refs {
        let key = keys::ref_key(req.repo, &update.name);
        if !snap.contains(&key) {
            return Err(internal("unacquired ref observation"));
        }
        let observed = snap
            .get(&key)
            .map(codec::decode_ref_id)
            .transpose()
            .map_err(corrupt)?
            .map_or(Observed::Absent(Revision([0; 32])), |value| {
                Observed::Present {
                    value,
                    revision: Revision(value),
                }
            });
        facts.refs.push((RefName(update.name.clone()), observed));
    }
    if let Some(replay) = req.replay {
        let key = keys::replay(&replay.scope);
        let observed = match snap.get(&key) {
            None => Observed::Absent(Revision([0; 32])),
            Some(raw) => {
                let record = codec::decode_replay_record(raw).map_err(corrupt)?;
                Observed::Present {
                    revision: Revision(hash(raw.as_bytes())),
                    value: ReplayFact {
                        fingerprint: record.fingerprint,
                        expires_ms: ms(record.expires_at_ms),
                        state: replay_state(&record),
                    },
                }
            }
        };
        facts.replay = Some(observed);
    }
    let mut claims = Vec::with_capacity(advance.ids.len());
    let mut rows = Vec::with_capacity(advance.ids.len());
    for id in advance.ids {
        let key = keys::ticket(id);
        let (observed, counted) = match snap.get(&key) {
            None => (Observed::Absent(Revision([0; 32])), false),
            Some(raw) => {
                let decoded = codec::decode_ticket(raw).map_err(meta_error)?;
                if tickets::ticket_id(&decoded.reservation_id) != *id {
                    return Err(internal("ticket reservation id mismatch"));
                }
                keys::reservation(&decoded.reservation_id)
                    .map_err(|_| internal("invalid ticket reservation id"))?;
                let counted = snap.get(&counted_key(advance, &decoded)).is_some();
                rows.push(decoded.clone());
                (
                    Observed::Present {
                        revision: Revision(hash(raw.as_bytes())),
                        value: ticket_fact(id, &decoded, advance),
                    },
                    counted,
                )
            }
        };
        facts.tickets.push((TicketId(*id), observed));
        claims.push(TicketClaim {
            ticket: TicketId(*id),
            // Proof rows were verified by `ticket_decision` before planning;
            // a claim reaching the atomic plan is proven.
            proof: UploadProof::Ready,
            counted,
        });
    }
    // Reservation observations: each ticket's bound row plus the admission's.
    let mut reservation_keys = Vec::new();
    for decoded in &rows {
        let id = ReservationId(hash(decoded.reservation_id.as_bytes()));
        let key = keys::reservation(&decoded.reservation_id).map_err(meta_error)?;
        reservation_keys.push((id.clone(), key.clone()));
        facts
            .reservations
            .push((id, reservation_observed(snap, &key)?));
    }
    let pending = req
        .pending
        .map(|pending| pending_binding(snap, clock, pending, &mut facts, &mut reservation_keys))
        .transpose()?;
    let storage = storage_accounting(req, snap, clock, advance, &mut facts, &mut reservation_keys)?;
    let request = TicketedAdvanceRequest {
        write,
        tickets: &claims,
        verification: mkit_primitives::decision::ticketed::VerificationVerdict::Satisfied,
        storage,
        pending,
        authority_generation: req.authority_generation,
    };
    let limits = RefDecisionLimits {
        facts: 64,
        guards: 32,
        bytes: 65_536,
        work: 262_144,
        public_message_bytes: 512,
    };
    let guarded =
        decide_ticketed_advance(&request, &facts, limits).map_err(|f| failure_error(&f))?;
    let recorded = recorded_result(req, snap);
    Ok(Some(Decided {
        guarded: Box::new(guarded),
        tickets: rows,
        recorded,
        reservation_keys,
    }))
}

/// The marker or membership row `plan_consumption` reads for `new_to_repo`.
fn counted_key(
    advance: &crate::pipeline::advance::AdvanceWrite<'_>,
    ticket: &TicketV1,
) -> crate::store::Key {
    if advance.counts_inline() {
        keys::repo_storage_pack(&ticket.repo, &ticket.pack_id)
    } else {
        keys::membership(&ticket.repo, &ticket.pack_id)
    }
}

fn ticket_fact(
    id: &mkit_core::hash::Hash,
    t: &TicketV1,
    advance: &crate::pipeline::advance::AdvanceWrite<'_>,
) -> TicketFact {
    TicketFact {
        ticket: TicketId(*id),
        repository: RepositoryId(hash(
            repo_storage::identity(&advance.repo_id.namespace, &t.repo).as_bytes(),
        )),
        name: RefName(t.ref_name.clone()),
        signer: t.signer,
        pack: PackSource {
            id: t.pack_id,
            len: t.bytes,
            // The ticket binds one immutable pack version.
            binding: SourceBinding(t.pack_id),
        },
        part_bytes: t.part_size,
        created_ms: t.created_at_ms,
        expires_ms: t.expires_at_ms,
        reservation: ReservationId(hash(t.reservation_id.as_bytes())),
        authority_generation: t.authority_generation,
        upload_session: t.upload_session.clone(),
    }
}

/// Decode a reservation row into its semantic observation. `ticket` binds a
/// `Ticketed` row to the consuming ticket, matching the reference's
/// `reservation()` binding check.
fn reservation_observed(
    snap: &Snapshot,
    key: &Key,
) -> Result<Observed<ReservationFact>, ServerError> {
    match snap.get(key) {
        None => Ok(Observed::Absent(Revision([0; 32]))),
        Some(raw) => {
            let row = codec::decode_reservation(raw).map_err(meta_error)?;
            let value = match &row {
                ReservationV1::Pending {
                    repository,
                    created_at_ms,
                    reconcile_at_ms,
                    op,
                    ..
                } => ReservationFact::Pending {
                    repository: RepositoryId(hash(repository.as_bytes())),
                    created_ms: *created_at_ms,
                    reconcile_ms: *reconcile_at_ms,
                    op: match op {
                        codec::PendingOp::Write => ReservationOp::Write,
                        codec::PendingOp::Read => ReservationOp::Read,
                    },
                },
                ReservationV1::Ticketed { ticket_id } => {
                    ReservationFact::Ticketed(TicketId(*ticket_id))
                }
                other => ReservationFact::Terminal(terminal_fact_row(other)?),
            };
            Ok(Observed::Present {
                value,
                revision: Revision(hash(raw.as_bytes())),
            })
        }
    }
}

/// Decode a terminal reservation row for a stored observation.
fn terminal_fact_row(
    row: &ReservationV1,
) -> Result<mkit_primitives::decision::ReservationTerminal, ServerError> {
    use mkit_primitives::decision::{
        RefValue, ReservationAccounting, ReservationTerminal, ReservationTerminalKind,
    };
    let (repository, occurred_ms, kind) = match row {
        ReservationV1::Committed {
            repository,
            occurred_at_ms,
            bytes_stored,
            new_to_repo,
            new_to_store,
            refs,
            ..
        } => (
            repository,
            *occurred_at_ms,
            ReservationTerminalKind::Committed {
                refs: refs
                    .iter()
                    .map(|r| RefValue {
                        name: RefName(r.name.clone()),
                        value: r.new,
                    })
                    .collect(),
                accounting: ReservationAccounting {
                    bytes_stored: *bytes_stored,
                    new_to_repository: *new_to_repo,
                    new_to_store: *new_to_store,
                },
            },
        ),
        ReservationV1::Aborted {
            repository,
            occurred_at_ms,
            reason,
            detail,
            ..
        } => (
            repository,
            *occurred_at_ms,
            ReservationTerminalKind::Aborted {
                reason: abort_reason(*reason),
                detail: detail.clone(),
            },
        ),
        ReservationV1::Expired {
            repository,
            occurred_at_ms,
        } => (
            repository,
            *occurred_at_ms,
            ReservationTerminalKind::Expired,
        ),
        ReservationV1::RepoStorageChanged {
            repository,
            occurred_at_ms,
            stored_bytes,
            version,
        } => (
            repository,
            *occurred_at_ms,
            ReservationTerminalKind::StorageChanged {
                stored_bytes: *stored_bytes,
                version: *version,
            },
        ),
        ReservationV1::ReadServed { .. } => {
            return Err(internal("read reservation on a write path"));
        }
        _ => return Err(internal("unsupported reservation row")),
    };
    Ok(ReservationTerminal {
        repository: RepositoryId(hash(repository.as_bytes())),
        occurred_ms,
        kind,
    })
}

fn abort_reason(reason: codec::AbortReason) -> mkit_primitives::decision::ReservationAbortReason {
    use mkit_primitives::decision::ReservationAbortReason as S;
    match reason {
        codec::AbortReason::Unspecified => S::Unspecified,
        codec::AbortReason::RefConflict => S::RefConflict,
        codec::AbortReason::EpochMismatch => S::EpochMismatch,
        codec::AbortReason::PackMissing => S::PackMissing,
        codec::AbortReason::ReplayRace => S::ReplayRace,
        codec::AbortReason::Internal => S::Internal,
        codec::AbortReason::Abandoned => S::Abandoned,
    }
}

/// Project the pending admission guard into the semantic request and record
/// its observation for the sealed fence.
fn pending_binding(
    snap: &Snapshot,
    clock: &PlanClock,
    pending: &crate::pipeline::reservation::PendingGuard,
    facts: &mut Facts,
    reservation_keys: &mut Vec<(ReservationId, Key)>,
) -> Result<PendingBinding, ServerError> {
    let row = codec::decode_reservation(&pending.value).map_err(meta_error)?;
    let ReservationV1::Pending {
        repository,
        created_at_ms,
        reconcile_at_ms,
        op,
        ..
    } = &row
    else {
        return Err(internal("pending reservation row changed class"));
    };
    let id = ReservationId(hash(pending.rid.as_bytes()));
    let expected = Observed::Present {
        revision: Revision(hash(pending.value.as_bytes())),
        value: ReservationFact::Pending {
            repository: RepositoryId(hash(repository.as_bytes())),
            created_ms: *created_at_ms,
            reconcile_ms: *reconcile_at_ms,
            op: match op {
                codec::PendingOp::Write => ReservationOp::Write,
                codec::PendingOp::Read => ReservationOp::Read,
            },
        },
    };
    // The fresh observation the sealed guard fences, and the expected row
    // admission wrote. A changed row retries before any ticket work.
    reservation_keys.push((id.clone(), pending.key.clone()));
    facts
        .reservations
        .push((id.clone(), reservation_observed(snap, &pending.key)?));
    Ok(PendingBinding {
        reservation: id,
        expected,
        occurred_ms: clock.plan_time_ms,
    })
}

/// The counting disposition plus the counter's observed row and the derived
/// outcome id a change would use.
fn storage_accounting(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
    advance: &crate::pipeline::advance::AdvanceWrite<'_>,
    facts: &mut Facts,
    reservation_keys: &mut Vec<(ReservationId, Key)>,
) -> Result<StorageAccounting, ServerError> {
    if !advance.count_storage {
        return Ok(StorageAccounting::Disabled);
    }
    if !advance.counts_inline() {
        return Ok(StorageAccounting::Relay);
    }
    let key = keys::repo_storage(&advance.repo_id.name);
    let observed = match snap.get(&key) {
        None => Observed::Absent(Revision([0; 32])),
        Some(raw) => {
            let counter = codec::decode_repo_storage(raw).map_err(meta_error)?;
            Observed::Present {
                value: StorageFact {
                    stored_bytes: counter.stored_bytes,
                    version: counter.version,
                },
                revision: Revision(hash(raw.as_bytes())),
            }
        }
    };
    // The outcome id derives from the counter version a change would write.
    let next_version = match &observed {
        Observed::Present { value, .. } => value.version.saturating_add(1),
        _ => 1,
    };
    let identity = repo_storage::identity(&req.namespace, &advance.repo_id.name);
    let outcome = ReservationId(hash(
        repo_storage::outcome_id(&identity, next_version).as_bytes(),
    ));
    // The derived outcome row's observation for the sealed absence guard.
    let outcome_key = keys::reservation(&repo_storage::outcome_id(&identity, next_version))
        .map_err(meta_error)?;
    reservation_keys.push((outcome.clone(), outcome_key));
    // The reference emits the outcome row's absence precondition without
    // reading it; the sealed expectation is the same unconditional absence.
    facts
        .reservations
        .push((outcome.clone(), Observed::Absent(Revision([0; 32]))));
    facts.storage = Some(observed.clone());
    Ok(StorageAccounting::Inline {
        observed,
        outcome,
        occurred_ms: clock.plan_time_ms,
    })
}

/// Map a decoded replay record to its semantic state.
fn replay_state(record: &crate::replay::ReplayRecord) -> ReplayState {
    match &record.state {
        crate::replay::ReplayState::InFlight { resumable } => ReplayState::InFlight {
            resumable: *resumable,
        },
        crate::replay::ReplayState::Committed(result) => {
            ReplayState::Committed(stored_terminal(result))
        }
    }
}

/// The semantic terminal for a recorded result. `Rejected` keeps the wire
/// code only when the permanent allowlist carries it; an unrecordable refusal
/// classifies like a fingerprint conflict on the reference path.
fn stored_terminal(result: &StoredResult) -> TerminalResult {
    match result {
        StoredResult::Rejected(rejection) => {
            match PermanentCode::from_code(rejection.code().as_str()) {
                Some(code) => TerminalResult::Rejected(PermanentRefusal {
                    code,
                    public_message: rejection.message().to_owned(),
                }),
                None => TerminalResult::Conflict(Vec::new()),
            }
        }
        _ => TerminalResult::Applied(Vec::new()),
    }
}

/// The stored commit a recorded replay row returns.
fn recorded_result(req: &WriteRequest<'_>, snap: &Snapshot) -> Option<StoredResult> {
    let replay = req.replay?;
    let raw = snap.get(&keys::replay(&replay.scope))?;
    let record = codec::decode_replay_record(raw).ok()?;
    match record.state {
        crate::replay::ReplayState::Committed(result)
            if record.fingerprint == replay.fingerprint =>
        {
            Some(result)
        }
        _ => None,
    }
}

/// A decision-crate failure means the host contract broke: missing or wrongly
/// scoped observations, or a shape the wire would never emit.
fn failure_error(failure: &mkit_primitives::error::Failure) -> ServerError {
    match failure.code {
        FailureCode::UnavailableInput => ServerError::unavailable("ticketed input not acquired"),
        _ => internal("portable ticketed decision failed"),
    }
}

/// Emit the ref half of the composed decision at `decide_write_result`'s
/// position: ref guards plus the conflict outcome or apply writes.
/// Completeness is deferred to [`check`] after every fragment lowered.
pub(super) fn lower_refs(
    decided: &Decided,
    req: &WriteRequest<'_>,
    pre: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let guarded = &decided.guarded;
    let mut required = Vec::new();
    if matches!(
        guarded.decision(),
        WriteDecision::Apply(_) | WriteDecision::Conflict { .. }
    ) {
        super::ref_decision::lower_ref_slots(req, guarded, &mut required)?;
    }
    pre.extend(required);
    match guarded.decision() {
        WriteDecision::Apply(effects) => {
            let writes = effects
                .refs
                .iter()
                .map(|effect| {
                    let key = keys::ref_key(req.repo, &effect.name.0);
                    effect.target.map_or(Write::Delete(key.clone()), |value| {
                        Write::Put(key, codec::encode_ref_id(&value))
                    })
                })
                .collect();
            Ok((None, writes))
        }
        WriteDecision::Conflict { current, .. } => {
            let observed = current
                .last()
                .ok_or_else(|| internal("missing ref conflict"))?;
            let result =
                match req.refs.iter().position(|update| {
                    update.name == observed.name.0
                        && matches!(
                            crate::refs::evaluate_condition(
                                observed.value.as_ref(),
                                &update.condition,
                            ),
                            crate::refs::CasDecision::Conflict(_)
                        )
                }) {
                    Some(0) => StoredResult::AdvanceRefs(
                        mkit_core::protocol::AdvanceOutcome::PackmapConflict,
                    ),
                    Some(_) => {
                        StoredResult::AdvanceRefs(mkit_core::protocol::AdvanceOutcome::HeadConflict)
                    }
                    None => return Err(internal("unmatched ref conflict")),
                };
            Ok((Some(result), Vec::new()))
        }
        _ => Err(internal("ticketed decision not terminal here")),
    }
}

/// Prove every sealed guard against the preconditions the batch emitted.
/// Runs after `plan_replay`, the last fragment to push preconditions.
pub(super) fn check(
    decided: &Decided,
    req: &WriteRequest<'_>,
    preconditions: &[Precondition],
) -> Result<(), ServerError> {
    let guarded = &decided.guarded;
    let discharged: Vec<_> = guarded
        .required_guards()
        .iter()
        .filter(|guard| decided.projects(guard, req, preconditions))
        .cloned()
        .collect();
    check_guard_completeness(guarded, &discharged)
        .map_err(|failure| internal(failure.code.as_str()))
}

impl Decided {
    /// Whether an emitted precondition discharges a sealed guard. The ref
    /// kinds reuse the A2 projection; ticket, reservation, storage and replay
    /// rows map by their store keys.
    fn projects(
        &self,
        guard: &RequiredGuard,
        req: &WriteRequest<'_>,
        conditions: &[Precondition],
    ) -> bool {
        match guard {
            RequiredGuard::RefValue { name, expected, .. } => {
                let key = keys::ref_key(req.repo, &name.0);
                match expected {
                    Observed::Absent(_) => conditions.contains(&Precondition::Absent(key)),
                    Observed::Present { value, .. } => {
                        conditions.contains(&Precondition::Equals(key, codec::encode_ref_id(value)))
                    }
                    _ => false,
                }
            }
            RequiredGuard::RefPresence { name, present, .. } => {
                let key = keys::ref_key(req.repo, &name.0);
                conditions.iter().any(|condition| match condition {
                    Precondition::Absent(candidate) => !*present && *candidate == key,
                    Precondition::Present(candidate) => *present && *candidate == key,
                    Precondition::Equals(candidate, value) => {
                        *present && *candidate == key && codec::decode_ref_id(value).is_ok()
                    }
                    Precondition::NotAfter(_) => false,
                })
            }
            RequiredGuard::Ticket { id, expected } => {
                row_projects(keys::ticket(&id.0), expected, conditions)
            }
            RequiredGuard::Reservation { id, expected } => self
                .reservation_keys
                .iter()
                .find(|(rid, _)| rid == id)
                .is_some_and(|(_, key)| row_projects(key.clone(), expected, conditions)),
            RequiredGuard::Storage { expected, .. } => {
                let key = keys::repo_storage(req.repo);
                row_projects(key, expected, conditions)
            }
            RequiredGuard::Replay { scope, expected } => {
                let key = keys::replay(&scope.0);
                row_projects(key, expected, conditions)
            }
            _ => false,
        }
    }
}

/// The sealed ticket/reservation guard is discharged by `Equals` on the
/// stored row it observed, or `Absent` for an absent observation.
fn row_projects<T>(key: Key, expected: &Observed<T>, conditions: &[Precondition]) -> bool {
    match expected {
        Observed::Absent(_) => conditions.contains(&Precondition::Absent(key)),
        Observed::Present { revision, .. } => conditions.iter().any(|condition| {
            matches!(condition, Precondition::Equals(k, value)
                if *k == key && Revision(hash(value.as_bytes())) == *revision)
        }),
        _ => false,
    }
}

/// The defensive `PackMissing` abort decided semantically: returns the
/// request positions `ticket_decision` may close. `None` leaves the
/// reference filter in place — the caller keeps behavior for shapes the
/// contract does not serve or a semantic refusal the reference planner
/// would not reach.
#[allow(clippy::too_many_arguments)] // The callsite passes its own locals through.
#[allow(clippy::too_many_lines)] // One observation pass plus the cleanup decision in callsite order.
pub(in crate::pipeline) fn cleanup_lost(
    auth: &crate::op::VerifiedAuth,
    advance: &crate::pipeline::advance::AdvanceWrite<'_>,
    head: &crate::op::RefUpdate,
    packmap: &crate::op::RefUpdate,
    rows: &[Result<TicketV1, ServerError>],
    heads: &crate::pipeline::advance::TicketHeads,
    snap: &Snapshot,
    business_now: i64,
) -> Result<Option<Vec<usize>>, ServerError> {
    use crate::pipeline::advance::Proof;
    let repository = RepositoryId(hash(
        repo_storage::identity(&advance.repo_id.namespace, &advance.repo_id.name).as_bytes(),
    ));
    let changes: Vec<_> = [packmap, head]
        .iter()
        .map(|update| RefChange {
            name: RefName(update.name.clone()),
            condition: update.condition,
            target: update.new,
        })
        .collect();
    let write = RefWriteRequest {
        repository,
        operation: Some(OperationId(auth.replay_scope)),
        kind: RefWriteKind::Advance,
        changes: &changes,
        admitted: &[],
        presence: None,
        signer: Some(advance.signer),
        replay: None,
        ancestry: &[],
        now_ms: ms(business_now),
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
    let mut facts = Facts {
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
        storage: None,
    };
    let mut claims = Vec::with_capacity(advance.ids.len());
    for (i, row) in rows.iter().enumerate() {
        let id = &advance.ids[i];
        // A row the reference validation already rejected may still be
        // present and decodable; feed the semantic its real fields so the
        // refusal reason (and the guard it would seal) stays honest.
        // Rows the reference marks unparseable or whose reservation id does
        // not bind the ticket have no honest fact; Absent still refuses, so
        // the failure boundary is preserved.
        let observed = snap.get(&keys::ticket(id)).and_then(|raw| {
            let decoded = codec::decode_ticket(raw).ok()?;
            (tickets::ticket_id(&decoded.reservation_id) == *id
                && keys::reservation(&decoded.reservation_id).is_ok())
            .then_some((raw, decoded))
        });
        let observed = match observed {
            None => Observed::Absent(Revision([0; 32])),
            Some((raw, decoded)) => Observed::Present {
                revision: Revision(hash(raw.as_bytes())),
                value: ticket_fact(id, &decoded, advance),
            },
        };
        facts.tickets.push((TicketId(*id), observed));
        // A failed HEAD is not a proven-missing pack: map it to
        // MarkerMissing so the semantic never aborts a ticket whose pack
        // state is merely unknown.
        let proof = match row {
            Ok(_) => match heads.proofs.get(id).map(|(_, proof)| proof) {
                Some(Ok(Proof::PackMissing)) => UploadProof::PackMissing,
                Some(Ok(Proof::Ready)) => UploadProof::Ready,
                _ => UploadProof::MarkerMissing,
            },
            Err(_) => UploadProof::Ready,
        };
        claims.push(TicketClaim {
            ticket: TicketId(*id),
            proof,
            counted: false,
        });
    }
    for row in rows.iter().flatten() {
        let rid = ReservationId(hash(row.reservation_id.as_bytes()));
        let key = keys::reservation(&row.reservation_id).map_err(meta_error)?;
        facts
            .reservations
            .push((rid, reservation_observed(snap, &key)?));
    }
    let request = TicketedAdvanceRequest {
        write,
        tickets: &claims,
        verification: mkit_primitives::decision::ticketed::VerificationVerdict::Satisfied,
        storage: StorageAccounting::Disabled,
        pending: None,
        authority_generation: None,
    };
    let limits = RefDecisionLimits {
        facts: 64,
        guards: 32,
        bytes: 65_536,
        work: 262_144,
        public_message_bytes: 512,
    };
    let Ok(guarded) = mkit_primitives::decision::ticketed::decide_ticket_cleanup(
        &request,
        "ticket pack missing after upload",
        ms(business_now),
        &facts,
        limits,
    ) else {
        return Ok(None);
    };
    let WriteDecision::Apply(effects) = &guarded.decision() else {
        return Ok(Some(Vec::new()));
    };
    let mut lost = Vec::with_capacity(effects.tickets.len());
    for transition in &effects.tickets {
        let Some(index) = advance.ids.iter().position(|id| *id == transition.id.0) else {
            return Err(internal("cleanup decided an unclaimed ticket"));
        };
        lost.push(index);
    }
    Ok(Some(lost))
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn exact_row_projection_rejects_substituted_values_at_the_same_key() {
        // Ticket, reservation, storage and replay use the same raw-row
        // projection. Each replacement is validly encoded for that row kind.
        let ticket = TicketV1 {
            authority_generation: None,
            repo: crate::RepoName::new("repo").unwrap(),
            ref_name: "refs/heads/main".into(),
            signer: [1; 32],
            pack_id: [2; 32],
            bytes: 44,
            part_size: 8 * 1024 * 1024,
            created_at_ms: 1,
            expires_at_ms: 1000,
            reservation_id: "s:projection".into(),
            upload_session: None,
        };
        let mut changed_ticket = ticket.clone();
        changed_ticket.bytes = 45;
        let replay = crate::replay::ReplayRecord {
            fingerprint: [3; 32],
            expires_at_ms: 1000,
            state: crate::replay::ReplayState::InFlight { resumable: false },
        };
        let mut changed_replay = replay.clone();
        changed_replay.fingerprint = [4; 32];
        for (key, first, second) in [
            (
                keys::ticket(&[1; 32]),
                codec::encode_ticket(&ticket),
                codec::encode_ticket(&changed_ticket),
            ),
            (
                keys::reservation("s:projection").unwrap(),
                codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: [1; 32] }),
                codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: [2; 32] }),
            ),
            (
                keys::repo_storage(&ticket.repo),
                crate::store::repo_storage::initial_counter(),
                codec::encode_repo_storage(&codec::RepoStorageV1 {
                    stored_bytes: 4,
                    version: 2,
                }),
            ),
            (
                keys::replay(&[1; 32]),
                codec::encode_replay_record(&replay),
                codec::encode_replay_record(&changed_replay),
            ),
        ] {
            let expected = Observed::Present {
                value: (),
                revision: Revision(hash(first.as_bytes())),
            };
            assert!(row_projects(
                key.clone(),
                &expected,
                &[Precondition::Equals(key.clone(), first)]
            ));
            assert!(!row_projects(
                key.clone(),
                &expected,
                &[Precondition::Equals(key, second)]
            ));
        }
    }
}
