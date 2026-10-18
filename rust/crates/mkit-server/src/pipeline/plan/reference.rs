//! Frozen planner decisions for semantic and lowering parity tests.
#![allow(clippy::too_many_lines)] // Preserve the pre-extraction oracle shape.
use super::*;

pub(crate) fn plan_write(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
) -> Result<Planned, ServerError> {
    if req.authority_generation.is_some() && req.authority_store != AuthorityStore::Guarded {
        return Err(ServerError::unavailable(
            "authority fencing requires transactional metadata",
        ));
    }
    if let Some(pending) = req.pending
        && snap.get(&pending.key) != Some(&pending.value)
    {
        return Err(ServerError::unavailable(
            "admission reservation changed; retry",
        ));
    }
    if let Some(result) = replayed_write(req, snap)? {
        if req.pending.is_some() {
            return Err(ServerError::aborted_retryable(
                "operation already in flight; retry",
            ));
        }
        return Ok(Planned::Done(result));
    }
    let tickets = req
        .advance
        .as_ref()
        .map(|advance| crate::pipeline::advance::validate(snap, advance, clock.business_now_ms))
        .transpose()?;
    let deadline = Precondition::NotAfter(req.pending.map_or(clock.deadline(), |pending| {
        clock.deadline().min(pending.apply_deadline_ms)
    }));
    let mut pre = vec![deadline.clone()];
    let mut puts = Vec::new();

    if let Some(lease) = req.lease {
        pre.push(guard(keys::epoch_lease(), snap));
        if lease.install {
            puts.push(Write::Put(
                keys::epoch_lease(),
                codec::encode_epoch_lease(&lease.value),
            ));
        }
    }
    let epoch_index = match req.grant.as_ref() {
        Some(grant) => {
            if let Some(lease) = req.lease {
                if lease.value.epoch != grant.epoch {
                    return Err(epoch_moved());
                }
                None
            } else {
                let key = keys::grant_epoch();
                let stored = snap.get(&key).map(codec::decode_u64).transpose();
                if stored.map_err(corrupt)?.unwrap_or(0) != grant.epoch {
                    return Err(epoch_moved());
                }
                pre.push(guard(key, snap));
                Some(pre.len() - 1)
            }
        }
        None => None,
    };
    if req.lease.is_none() && req.authority_store != AuthorityStore::RefsOnly {
        let mode = snap
            .get(&keys::lease_recovery())
            .map(codec::decode_lease_recovery)
            .transpose()
            .map_err(corrupt)?;
        if req.authority_generation.is_none()
            && (snap.get(&keys::authority_generation()).is_some()
                || mode.is_some_and(|m| m.authority_fence == Some(true)))
        {
            return Err(ServerError::unavailable(
                "persisted authority fence requires enabled executor",
            ));
        }
        if req.authority_store == AuthorityStore::Guarded {
            pre.push(guard(keys::lease_recovery(), snap));
            if req.authority_generation.is_none() {
                pre.push(guard(keys::authority_generation(), snap));
            }
        }
    }
    if let Some(generation) = req.authority_generation {
        let current = if let Some(lease) = req.lease {
            lease
                .value
                .authority_generation
                .ok_or_else(|| ServerError::unavailable("lease missing authority generation"))?
        } else {
            snap.get(&keys::authority_generation())
                .map(codec::decode_u64)
                .transpose()
                .map_err(corrupt)?
                .unwrap_or(0)
        };
        if current != generation {
            return Err(crate::authority::moved());
        }
        if tickets.as_ref().is_some_and(|tickets| {
            tickets
                .iter()
                .any(|ticket| ticket.authority_generation != Some(generation))
        }) {
            return Err(crate::authority::moved());
        }
        if req.lease.is_none() {
            pre.push(guard(keys::authority_generation(), snap));
        }
    }
    if req.layout_version {
        let key = keys::layout_version();
        match snap.get(&key).map(codec::decode_u32).transpose() {
            Ok(None) => puts.push(Write::Put(key.clone(), codec::encode_u32(LAYOUT_VERSION))),
            Ok(Some(LAYOUT_VERSION)) => {}
            Ok(Some(other)) => return Err(corrupt(format!("layout version {other}"))),
            Err(e) => return Err(corrupt(e)),
        }
        pre.push(guard(key, snap));
    }
    if req.mark_repo_known {
        let key = keys::repo_known(req.repo);
        if snap.get(&key).is_none() {
            pre.push(Precondition::Absent(key.clone()));
            puts.push(Write::Put(key, Value::default()));
        }
    }
    for charge in req.charges {
        plan_charge(charge, snap, clock.business_now_ms, &mut pre, &mut puts)?;
    }
    plan_namespace(req, snap, clock, &mut pre, &mut puts)?;

    let (on_commit, ref_puts, conflict) =
        decide_write_result(req, snap, clock, &mut pre, &mut puts)?;
    if conflict && let Some(advance) = &req.advance {
        crate::pipeline::advance::guard_examined_tickets(snap, advance, &mut pre);
    }
    if conflict && req.replay.is_none() && req.charges.is_empty() && req.pending.is_none() {
        return Ok(Planned::Done(on_commit));
    }
    if !conflict {
        puts.extend(ref_puts);
    }
    if req.advance.is_some()
        || req.ref_index.is_some() && !req.refs.is_empty()
        || !conflict && req.implicit.is_some()
        || req.pending.is_some() && req.kind != WriteKind::BeginUpload
        || req.publication.is_some() && !req.refs.is_empty()
    {
        let mut outbox = OutboxBuilder::new(
            snap.get(&keys::outbox_sequence()),
            snap.get(&keys::outcome_backlog()),
        )
        .map_err(meta_error)?;
        if !conflict && let (Some(advance), Some(tickets)) = (&req.advance, tickets.as_deref()) {
            crate::pipeline::advance::plan_consumption(
                snap,
                advance,
                tickets,
                req.refs,
                clock,
                &mut pre,
                &mut puts,
                &mut outbox,
                req.publication.is_none(),
            )?;
        }
        if !conflict && let Some(implicit) = &req.implicit {
            crate::store::repo_storage::plan_count(
                implicit.repo_id,
                implicit.counted,
                implicit.source,
                implicit.shards,
                |key| snap.get(key),
                |pack| snap.get(&keys::membership(req.repo, pack)).is_some(),
                clock.plan_time_ms,
                &mut outbox,
                &mut pre,
                &mut puts,
            )
            .map_err(meta_error)?;
        }
        if !conflict {
            add_ref_index_relays(req, &mut outbox);
            if let Some(implicit) = &req.implicit
                && req.publication.is_none()
            {
                tickets::plan_membership(
                    req.repo,
                    implicit.packs,
                    implicit.source,
                    implicit.shards,
                    implicit.repo_id,
                    &mut outbox,
                    &mut puts,
                );
            }
        }
        if !conflict
            && req.rejection.is_none()
            && !req.refs.is_empty()
            && let Some(publication) = &req.publication
        {
            let name = crate::store::publication::sequence_ref(&req.refs[0].name);
            let pair = crate::pipeline::clearance::resulting_pair(req.repo, req.refs, snap)?;
            let additions = tickets
                .as_ref()
                .map(|ts| ts.iter().map(|t| t.pack_id).collect())
                .or_else(|| req.implicit.as_ref().map(|i| i.packs.to_vec()))
                .unwrap_or_default();
            let operation = req.replay.map_or([0; 32], |r| r.scope);
            let mut advance = publication.prepared.cloned().unwrap_or_else(|| {
                crate::pipeline::clearance::immediate(pair.clone(), operation, additions.clone())
            });
            if advance.value != pair {
                return Err(ServerError::unavailable("publication pair changed; retry"));
            }
            if publication.prepared.is_some() {
                let current = crate::store::publication::Publication::decode(
                    snap.get(&keys::publication(req.repo, &name)),
                )
                .map_err(meta_error)?;
                match publication.bound {
                    Some(bound)
                        if bound == crate::pipeline::clearance::PreparedAt::of(&current) => {}
                    Some(_) => {
                        return Err(ServerError::unavailable("publication state changed; retry"));
                    }
                    None => return Err(internal("publication proof is not bound to its state")),
                }
            }
            advance.additions = additions;
            advance.operation = operation;
            crate::store::publication::append(
                publication.repo,
                &name,
                publication.source,
                publication.shards,
                snap.get(&keys::publication(req.repo, &name)),
                advance,
                req.refs.iter().any(|u| u.new.is_none()),
                &mut pre,
                &mut puts,
                &mut outbox,
            )
            .map_err(meta_error)?;
        }
        if let Some(pending) = req.pending {
            let record = if conflict {
                codec::ReservationV1::Aborted {
                    repository: pending.repository.clone(),
                    occurred_at_ms: clock.plan_time_ms,
                    reason: codec::AbortReason::RefConflict,
                    detail: String::new(),
                    procedure: pending.procedure,
                }
            } else {
                codec::ReservationV1::Committed {
                    repository: pending.repository.clone(),
                    occurred_at_ms: clock.plan_time_ms,
                    bytes_stored: 0,
                    new_to_repo: 0,
                    new_to_store: 0,
                    refs: req
                        .refs
                        .iter()
                        .map(|update| codec::OutcomeRef {
                            name: update.name.clone(),
                            new: update.new,
                            deleted: update.new.is_none(),
                        })
                        .collect(),
                    procedure: pending.procedure,
                }
            };
            outbox.outcome(
                &pending.rid,
                &pending.value,
                Terminal::new(record).map_err(meta_error)?,
            );
        }
        outbox.relay_at(clock.plan_time_ms);
        outbox.try_finish(&mut pre, &mut puts).map_err(meta_error)?;
    }
    let pending_index = req.pending.and_then(|pending| pre.iter().position(|condition| matches!(condition, Precondition::Equals(key, value) if key == &pending.key && value == &pending.value)));

    let replay_index = match req.replay {
        Some(replay) => {
            let index = pre.len();
            if let Some(done) =
                plan_replay(req.kind, replay, snap, &on_commit, &mut pre, &mut puts)?
            {
                if req.pending.is_some() {
                    return Err(ServerError::aborted_retryable(
                        "operation already in flight; retry",
                    )
                    .with_abort_cause(AbortCause::ReplayRace));
                }
                return Ok(Planned::Done(done));
            }
            Some(index)
        }
        None => None,
    };

    let budget = MAX_BATCH_OPS.saturating_sub(pre.len() + puts.len());
    let prune = plan_prune(req, snap, &deadline, budget)?;
    let mut writes = prune.as_ref().map(|b| b.writes.clone()).unwrap_or_default();
    writes.extend(puts);
    let prune_from = pre.len();
    if let Some(prune) = &prune {
        pre.extend(prune.preconditions.iter().skip(1).cloned());
    }
    Ok(Planned::Apply(Plan {
        batch: Batch {
            preconditions: pre,
            writes,
        },
        on_commit,
        replay_index,
        epoch_index,
        pending_index,
        prune,
        prune_from,
    }))
}

fn decide_write_result(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(StoredResult, Vec<Write>, bool), ServerError> {
    if req.kind != WriteKind::UploadCommit
        && let Some(rejection) = req.rejection
    {
        if let Some((name, value)) = req.denial_ref {
            let key = keys::ref_key(req.repo, name);
            pre.push(match value {
                Some(value) => Precondition::Equals(key, codec::encode_ref_id(&value)),
                None => Precondition::Absent(key),
            });
        }
        return Ok((StoredResult::Rejected(rejection.clone()), Vec::new(), false));
    }
    let (outcome, ref_puts) = decide_refs(req, snap, pre)?;
    let conflict = outcome.is_some();
    let ticket_result = req
        .begin
        .map(|b| crate::pipeline::begin::plan(b, snap, clock, pre, puts))
        .transpose()?;
    let on_commit = if let Some(result) = outcome.or(ticket_result) {
        result
    } else {
        match req.kind {
            WriteKind::BeginUpload => {
                return Err(ServerError::internal(
                    "ticket plan failed",
                    "missing BeginUpload plan",
                ));
            }
            WriteKind::UpdateRef => StoredResult::UpdateRef(UpdateRefResult::Committed),
            WriteKind::AdvanceRefs => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            WriteKind::UploadReserve | WriteKind::UploadCommit => {
                req.rejection.map_or(StoredResult::UploadPack, |r| {
                    StoredResult::Rejected(r.clone())
                })
            }
        }
    };
    Ok((on_commit, ref_puts, conflict))
}

fn decide_refs(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    pre: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let mut puts = Vec::new();
    for (i, update) in req.refs.iter().enumerate() {
        let key = keys::ref_key(req.repo, &update.name);
        let current = snap.get(&key).map(codec::decode_ref_id).transpose();
        let current = current.map_err(corrupt)?;
        let resolved = req
            .resolved_ref_updates
            .iter()
            .find(|resolved| resolved.name == update.name);
        if let Some(requirement) = req
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
                    pre.push(if required {
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
                    if update.condition == RefWriteCondition::Any {
                        pre.push(if resolved.prior_present() {
                            Precondition::Present(key.clone())
                        } else {
                            Precondition::Absent(key.clone())
                        });
                    }
                }
                if update.condition != RefWriteCondition::Any {
                    pre.push(guard(key.clone(), snap));
                }
                puts.push(match update.new {
                    Some(id) => Write::Put(key, codec::encode_ref_id(&id)),
                    None => Write::Delete(key),
                });
            }
            CasDecision::Conflict(_) => {
                pre.push(guard(key, snap));
                let result = match (req.kind, i) {
                    (WriteKind::UpdateRef, _) => {
                        StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                    }
                    (WriteKind::AdvanceRefs, 0) => {
                        StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict)
                    }
                    _ => StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
                };
                return Ok((Some(result), Vec::new()));
            }
            CasDecision::Invalid(msg) => return Err(ServerError::invalid_argument(msg)),
        }
    }
    Ok((None, puts))
}
