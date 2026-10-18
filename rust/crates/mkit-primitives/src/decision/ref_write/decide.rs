use super::{
    AncestryResult, RefDecisionLimits, RefWriteKind, RefWriteRequest,
    checks::{bounds, failure},
};
use crate::replay::{
    RecordedResult, ReplayDecision, ReplayObservation, ReplayStateView, classify_replay,
};
use crate::{
    decision::{
        AcceptanceEffects, Guarded, LifecycleState, Observed, PermanentCode, PermanentRefusal,
        RefEffect, RefValue, ReplayState, ReplayTransition, RequiredGuard, RequiredSourceFence,
        RetryReason, Snapshot, TerminalResult, WriteDecision,
    },
    error::{Failure, FailureCode},
};
use mkit_core::{
    hash::Hash,
    refs::{RefWriteCondition, validate_ref_name},
};

pub(crate) struct Attempt<'a> {
    pub(crate) req: &'a RefWriteRequest<'a>,
    snapshot: &'a Snapshot,
    pub(crate) guards: Vec<RequiredGuard>,
    pub(crate) limits: RefDecisionLimits,
}

impl<'a> Attempt<'a> {
    pub(crate) fn new(
        req: &'a RefWriteRequest<'a>,
        snapshot: &'a Snapshot,
        limits: RefDecisionLimits,
    ) -> Result<Self, Failure> {
        let mut attempt = Self {
            req,
            snapshot,
            guards: Vec::new(),
            limits,
        };
        attempt
            .guards
            .try_reserve_exact(limits.guards.min(64) as usize)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        Ok(attempt)
    }
}

/// Decide a single write, paired advance, or exact deletion with all read guards.
///
/// The host authenticates the current envelope before invoking this function.
/// Applicability and authoritative observations are trusted host inputs; missing
/// applicable acquisition is an error, never inferred absence. Completed replay
/// is returned before new authorization, content, policy, or admission work.
/// Source fences remain separate pre-apply checks, not cross-repository CAS.
///
/// # Errors
/// `UnavailableInput` for unacquired applicable facts, `InvalidResponse` for
/// ambiguous or wrongly scoped observations, and `ResourceLimit` for explicit
/// finite input/output/work limits. Errors produce no effects or terminal replay.
pub fn decide_ref_write(
    request: &RefWriteRequest<'_>,
    snapshot: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<Guarded<WriteDecision>, Failure> {
    if request.changes.len() > 2 {
        return Err(failure(FailureCode::InvalidRefRequest));
    }
    bounds(request, snapshot, limits)?;
    let mut attempt = Attempt::new(request, snapshot, limits)?;
    let decision = if let Some(recorded) = attempt.replay()? {
        recorded
    } else {
        if invalid_shape(request) {
            return Err(failure(FailureCode::InvalidRefRequest));
        }
        match attempt.context()? {
            Some(refusal) => refusal,
            None => attempt.refs()?,
        }
    };
    let source_fences = if matches!(decision, WriteDecision::ReturnRecorded(_)) {
        Vec::new()
    } else {
        request
            .required
            .source
            .into_iter()
            .map(|fence| RequiredSourceFence::Published(Box::new(fence.clone())))
            .collect()
    };
    Ok(Guarded {
        repository: request.repository,
        decision,
        required: attempt.guards,
        source_fences,
    })
}

/// Add one guard, dropping an exact duplicate.
///
/// A guard that contradicts one already collected for the same identity names
/// an Apply (or refusal) that could never commit, so it is a failure rather
/// than a decision.
pub(crate) fn push_guard(
    guards: &mut Vec<RequiredGuard>,
    limit: u32,
    guard: RequiredGuard,
) -> Result<(), Failure> {
    if guards.contains(&guard) {
        return Ok(());
    }
    if guards
        .iter()
        .any(|other| !super::complete::compatible(other, &guard))
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    if guards.len() >= limit as usize {
        return Err(failure(FailureCode::ResourceLimit));
    }
    guards
        .try_reserve(1)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    guards.push(guard);
    Ok(())
}

fn invalid_shape(request: &RefWriteRequest<'_>) -> bool {
    let pair = matches!(
        request.kind,
        RefWriteKind::Advance | RefWriteKind::DeletePair
    );
    if request.changes.len() != if pair { 2 } else { 1 } {
        return true;
    }
    if request
        .changes
        .iter()
        .any(|change| !change.name.0.starts_with("refs/") || !validate_ref_name(&change.name.0))
    {
        return true;
    }
    // A pair is positional: any two valid ref names decide under the first
    // change's outcome class (SPEC-TRANSPORT-CONNECT §4 leaves the canonical
    // packmap/head pairing optional to the server).
    if matches!(
        request.kind,
        RefWriteKind::Delete | RefWriteKind::DeletePair
    ) {
        if request.changes.iter().any(|change| {
            change.target.is_some() || !matches!(change.condition, RefWriteCondition::Match(_))
        }) {
            return true;
        }
    } else if request.changes.iter().any(|change| change.target.is_none()) {
        return true;
    }
    false
}

impl Attempt<'_> {
    pub(crate) fn add(&mut self, guard: RequiredGuard) -> Result<(), Failure> {
        push_guard(&mut self.guards, self.limits.guards, guard)
    }

    pub(crate) fn reject(
        &self,
        code: PermanentCode,
        message: &str,
    ) -> Result<WriteDecision, Failure> {
        if message.len() > self.limits.public_message_bytes as usize
            || (message.len() as u64).saturating_mul(2) > self.limits.bytes
        {
            return Err(failure(FailureCode::ResourceLimit));
        }
        let mut public_message = String::new();
        public_message
            .try_reserve_exact(message.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        public_message.push_str(message);
        let refusal = PermanentRefusal {
            code,
            public_message,
        };
        let terminal = None;
        Ok(WriteDecision::Reject {
            refusal,
            terminal,
            reservation: None,
        })
    }

    /// A refusal the replay record will store. Storing a permanent answer is
    /// only sound while the original authorization still holds, so grant,
    /// authority and lifecycle are decided and guarded first; a stale binding
    /// then yields its own unrecorded answer instead of a stored refusal.
    pub(crate) fn reject_recorded(
        &mut self,
        code: PermanentCode,
        message: &str,
    ) -> Result<WriteDecision, Failure> {
        let recording =
            self.req.replay.is_some() && matches!(self.snapshot.replay, Some(Observed::Absent(_)));
        if recording && let Some(decision) = self.authorized()? {
            return Ok(decision);
        }
        let mut decision = self.reject(code, message)?;
        if recording
            && let WriteDecision::Reject {
                refusal, terminal, ..
            } = &mut decision
        {
            *terminal = Some(TerminalResult::Rejected(refusal.clone()));
        }
        Ok(decision)
    }

    fn authorized(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(decision) = self.grant()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.authority()? {
            return Ok(Some(decision));
        }
        self.lifecycle()
    }

    pub(crate) fn replay(&mut self) -> Result<Option<WriteDecision>, Failure> {
        let Some(replay) = &self.req.replay else {
            return Ok(None);
        };
        let observed = self
            .snapshot
            .replay
            .as_ref()
            .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
        if matches!(observed, Observed::Present { value, .. } if value.scope != replay.scope) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        self.add(RequiredGuard::Replay {
            scope: replay.scope.clone(),
            expected: observed.clone(),
        })?;
        let record = match observed {
            Observed::Absent(_) => None,
            Observed::Present { value, .. } => Some(ReplayObservation {
                fingerprint: value.fingerprint,
                state: match &value.state {
                    ReplayState::InFlight { resumable } => ReplayStateView::InFlight {
                        resumable: *resumable,
                    },
                    ReplayState::Committed(result) => ReplayStateView::Committed(match result {
                        TerminalResult::Rejected(refusal) => {
                            RecordedResult::rejection(result, refusal.code.as_str(), false)
                                .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                        }
                        _ => RecordedResult::success(result),
                    }),
                },
            }),
        };
        match classify_replay(record, &replay.fingerprint) {
            ReplayDecision::Fresh => Ok(None),
            ReplayDecision::Recorded(result) => {
                Ok(Some(WriteDecision::ReturnRecorded(result.clone())))
            }
            ReplayDecision::Resume | ReplayDecision::InFlight => {
                Ok(Some(WriteDecision::Retry(RetryReason::InFlight)))
            }
            ReplayDecision::Conflict => self
                .reject(
                    PermanentCode::InvalidArgument,
                    "nonce reused for a different operation",
                )
                .map(Some),
        }
    }

    pub(crate) fn context(&mut self) -> Result<Option<WriteDecision>, Failure> {
        // An applicable original acceptance bound also fences a fresh refusal.
        if let Some(decision) = self.validity()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.source()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.policy()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.membership()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.ancestry()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.denial()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.grant()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.authority()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.lifecycle()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.admission()? {
            return Ok(Some(decision));
        }
        if let Some(decision) = self.publication()? {
            return Ok(Some(decision));
        }
        Ok(None)
    }

    fn source(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(source) = self.req.required.source {
            if source.repository != self.req.repository
                || !source.name.0.starts_with("refs/")
                || !validate_ref_name(&source.name.0)
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
            if self.req.kind != RefWriteKind::Advance
                || self
                    .req
                    .changes
                    .iter()
                    .any(|change| change.condition != RefWriteCondition::Missing)
            {
                return Err(failure(FailureCode::InvalidRefRequest));
            }
            // SPEC-SERVER §9.3: an unreadable, absent, unpublished or unpaired
            // source is uniformly "source not found".
            if !matches!(&source.read_authority, Observed::Present { value, .. } if value.ready) {
                return self
                    .reject(PermanentCode::NotFound, "source not found")
                    .map(Some);
            }
            let Observed::Present { value, .. } = &source.publication else {
                return self
                    .reject(PermanentCode::NotFound, "source not found")
                    .map(Some);
            };
            if value.published_prefix > value.sequence
                || value.deletion_boundary > value.published_prefix
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
            if value.sequence == 0 || value.head.is_none() || value.packmap.is_none() {
                return self
                    .reject(PermanentCode::NotFound, "source not found")
                    .map(Some);
            }
            // The destination pair is the pair captured from this publication
            // row. A difference means the source moved since capture: nothing
            // is recorded, and the caller reacquires and redecides (§9.3 "otherwise
            // retryable unavailable"; the expected-tip comparison belongs to the host).
            if self.req.changes[0].target != value.packmap
                || self.req.changes[1].target != value.head
            {
                return Ok(Some(WriteDecision::Retry(RetryReason::Unavailable)));
            }
        }
        Ok(None)
    }

    fn authority(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(bound) = &self.req.required.authority {
            let observed = self
                .snapshot
                .authority
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            if matches!(observed, Observed::Present { value, .. } if value.namespace != bound.namespace)
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
            self.add(RequiredGuard::Authority {
                namespace: bound.namespace.clone(),
                expected: observed.clone(),
            })?;
            match observed {
                Observed::Present { value, .. }
                    if value.ready
                        && value.generation == bound.generation
                        && value.mode == bound.mode => {}
                Observed::Present { value, .. } if !value.ready => {
                    return Ok(Some(WriteDecision::Retry(RetryReason::Unavailable)));
                }
                _ => {
                    return self
                        .reject(
                            PermanentCode::PermissionDenied,
                            "namespace authority generation changed",
                        )
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    fn grant(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(bound) = &self.req.required.grant {
            let observed = self
                .snapshot
                .grant
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            if matches!(observed, Observed::Present { value, .. } if value.namespace != bound.namespace)
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
            self.add(RequiredGuard::Grant {
                namespace: bound.namespace.clone(),
                expected: observed.clone(),
            })?;
            match observed {
                Observed::Present { value, .. }
                    if value.grant == bound.grant && value.epoch == bound.epoch =>
                {
                    if value.presence != self.req.presence.as_ref().map(|(_, required)| *required) {
                        return Err(failure(FailureCode::InvalidResponse));
                    }
                }
                _ => {
                    return self
                        .reject(
                            PermanentCode::PermissionDenied,
                            "write grant epoch changed; re-authorize",
                        )
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    fn lifecycle(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(incarnation) = self.req.required.incarnation {
            let observed = self
                .snapshot
                .lifecycle
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Repository {
                id: self.req.repository,
                expected: observed.clone(),
            })?;
            match observed {
                Observed::Present { value, .. }
                    if value.incarnation == incarnation
                        && value.state == LifecycleState::Active => {}
                _ => {
                    // Lifecycle enforcement has no generic public refusal in
                    // the reference ref path. A stale binding only retries;
                    // the host retains its existing lifecycle policy boundary.
                    return Ok(Some(WriteDecision::Retry(RetryReason::ChangedFacts)));
                }
            }
        }
        Ok(None)
    }

    fn policy(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(required) = self.req.required.policy {
            let observed = self
                .snapshot
                .policy
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Policy {
                repository: self.req.repository,
                expected: observed.clone(),
            })?;
            let Observed::Present { value, .. } = observed else {
                return Err(failure(FailureCode::InvalidResponse));
            };
            if required.signer_restricted
                && self
                    .req
                    .signer
                    .is_none_or(|signer| !value.allowed_signers.contains(&signer))
            {
                return self
                    .reject_recorded(
                        PermanentCode::PermissionDenied,
                        "signer not allowed for this ref",
                    )
                    .map(Some);
            }
        }
        Ok(None)
    }

    fn membership(&mut self) -> Result<Option<WriteDecision>, Failure> {
        for object in self.req.required.members {
            let observed = self
                .snapshot
                .members
                .iter()
                .find(|member| &member.object == object)
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Membership {
                repository: self.req.repository,
                object: *object,
                expected: observed.observed.clone(),
            })?;
            match &observed.observed {
                Observed::Present { .. } => {}
                Observed::Absent(_)
                    if self.req.required.membership_window
                        == super::MembershipWindow::WithinLag =>
                {
                    return Ok(Some(WriteDecision::Retry(
                        RetryReason::MembershipNotVisible,
                    )));
                }
                Observed::Absent(_) => {
                    return self
                        .reject_recorded(PermanentCode::InvalidArgument, "open closure")
                        .map(Some);
                }
            }
        }
        if self.req.required.indexed_head
            && let Some(object) = self.req.changes.last().and_then(|change| change.target)
        {
            let member = self
                .snapshot
                .members
                .iter()
                .find(|member| member.object == object)
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Membership {
                repository: self.req.repository,
                object,
                expected: member.observed.clone(),
            })?;
            match &member.observed {
                Observed::Present { value, .. }
                    if matches!(
                        value.kind,
                        mkit_core::object::ObjectType::Commit
                            | mkit_core::object::ObjectType::Remix
                            | mkit_core::object::ObjectType::Tag
                    ) => {}
                Observed::Absent(_)
                    if self.req.required.membership_window
                        == super::MembershipWindow::WithinLag =>
                {
                    return Ok(Some(WriteDecision::Retry(
                        RetryReason::MembershipNotVisible,
                    )));
                }
                _ => {
                    return self
                        .reject_recorded(PermanentCode::InvalidArgument, "open closure")
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    fn denial(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if self.req.required.denial {
            let observed = self
                .snapshot
                .denial
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Denial {
                repository: self.req.repository,
                expected: observed.clone(),
            })?;
            if let Observed::Present { value, .. } = observed {
                if !value.held.is_empty() {
                    return Ok(Some(WriteDecision::Retry(RetryReason::Unavailable)));
                }
                if !value.objects.is_empty() || !value.packs.is_empty() {
                    return self
                        .reject(PermanentCode::PermissionDenied, "object blocked")
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    fn admission(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(bound) = &self.req.required.admission {
            let observed = self
                .snapshot
                .admission
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            let operation = self
                .req
                .operation
                .as_ref()
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
            self.add(RequiredGuard::Admission {
                operation: operation.clone(),
                expected: observed.clone(),
            })?;
            let Observed::Present { value, .. } = observed else {
                return Err(failure(FailureCode::InvalidResponse));
            };
            if value.operation != *operation
                || value.effects != bound.effects
                || self.req.admitted.len() != self.req.changes.len()
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
            if value.presence.len() != self.req.admitted.len()
                || self.req.admitted.iter().any(|admitted| {
                    !value.presence.iter().any(|delta| {
                        delta.name == admitted.name
                            && delta.before == admitted.prior_present
                            && delta.after == admitted.target.is_some()
                    })
                })
            {
                return Err(failure(FailureCode::InvalidResponse));
            }
        }
        Ok(None)
    }

    fn publication(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if self.req.required.publication {
            let observed = self
                .snapshot
                .publication
                .as_ref()
                .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
            self.add(RequiredGuard::Publication {
                repository: self.req.repository,
                expected: observed.clone(),
            })?;
        }
        Ok(None)
    }

    fn validity(&mut self) -> Result<Option<WriteDecision>, Failure> {
        if let Some(instant_ms) = self.req.required.valid_through_ms {
            self.add(RequiredGuard::ValidThrough { instant_ms })?;
            if self.req.now_ms > instant_ms {
                return Ok(Some(WriteDecision::Retry(RetryReason::ChangedFacts)));
            }
        }
        Ok(None)
    }

    fn ancestry(&mut self) -> Result<Option<WriteDecision>, Failure> {
        let Some(required) = self.req.required.policy else {
            return Ok(None);
        };
        let deployment = matches!(&self.snapshot.policy, Some(Observed::Present { value, .. }) if value.fast_forward);
        if !deployment && !required.grant_fast_forward {
            return Ok(None);
        }
        let subject = self
            .req
            .changes
            .last()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let message = if deployment {
            "non-fast-forward update not allowed on this ref"
        } else {
            "write grant rejected: ref scope"
        };
        let Some(to) = subject.target else {
            return self
                .reject_recorded(PermanentCode::PermissionDenied, message)
                .map(Some);
        };
        if subject.condition == RefWriteCondition::Missing {
            return Ok(None);
        }
        let from = match subject.condition {
            RefWriteCondition::Missing => return Ok(None),
            RefWriteCondition::Match(expected) => expected,
            RefWriteCondition::Any => {
                let observed = self.observed(&subject.name)?.clone();
                self.add(RequiredGuard::RefValue {
                    repository: self.req.repository,
                    name: subject.name.clone(),
                    expected: observed.clone(),
                })?;
                let Some(from) = target(&observed) else {
                    return Ok(None);
                };
                from
            }
        };
        let proof = self
            .req
            .ancestry
            .iter()
            .find(|proof| proof.name == subject.name && proof.from == from && proof.to == to)
            .ok_or_else(|| failure(FailureCode::UnavailableInput))?;
        if proof.repository != self.req.repository {
            return Err(failure(FailureCode::InvalidResponse));
        }
        match proof.result {
            AncestryResult::Descendant => Ok(None),
            AncestryResult::Denied => self
                .reject_recorded(PermanentCode::PermissionDenied, message)
                .map(Some),
            AncestryResult::MembershipLag => Ok(Some(WriteDecision::Retry(
                RetryReason::MembershipNotVisible,
            ))),
        }
    }

    fn observed(&self, name: &crate::decision::RefName) -> Result<&Observed<Hash>, Failure> {
        self.snapshot
            .refs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| failure(FailureCode::UnavailableInput))
    }

    pub(crate) fn refs(&mut self) -> Result<WriteDecision, Failure> {
        for change in self.req.changes {
            let observed = self.observed(&change.name)?.clone();
            let value = target(&observed);
            if let Some((name, present)) = self.req.presence.as_ref()
                && *name == change.name
            {
                self.add(RequiredGuard::RefPresence {
                    repository: self.req.repository,
                    name: name.clone(),
                    present: value.is_some(),
                })?;
                if value.is_some() != *present {
                    return self.reject(
                        PermanentCode::PermissionDenied,
                        "write grant rejected: ref scope",
                    );
                }
            }
            let conflict = match change.condition {
                RefWriteCondition::Any => false,
                RefWriteCondition::Missing => value.is_some(),
                RefWriteCondition::Match(expected) => value != Some(expected),
            };
            if conflict || change.condition != RefWriteCondition::Any {
                self.add(RequiredGuard::RefValue {
                    repository: self.req.repository,
                    name: change.name.clone(),
                    expected: observed,
                })?;
            }
            if conflict {
                // Only the conflicting row belongs to the public result.
                // Earlier Any rows were not dependencies and must not leak an
                // unguarded value into a durable terminal answer.
                let current = vec![RefValue {
                    name: change.name.clone(),
                    value,
                }];
                let replay = self
                    .req
                    .replay
                    .as_ref()
                    .map(|_| TerminalResult::Conflict(current.clone()));
                return Ok(WriteDecision::Conflict {
                    current,
                    replay,
                    reservation: None,
                });
            }
            if !self.req.admitted.is_empty() {
                let admitted = self
                    .req
                    .admitted
                    .iter()
                    .find(|admitted| admitted.name == change.name)
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                self.add(RequiredGuard::RefPresence {
                    repository: self.req.repository,
                    name: change.name.clone(),
                    present: value.is_some(),
                })?;
                if admitted.target != change.target || admitted.prior_present != value.is_some() {
                    return Ok(WriteDecision::Retry(RetryReason::AdmittedRefChanged));
                }
            }
        }
        let refs: Vec<_> = self
            .req
            .changes
            .iter()
            .map(|change| RefEffect {
                name: change.name.clone(),
                target: change.target,
            })
            .collect();
        let replay = self.req.replay.as_ref().map(|replay| ReplayTransition {
            scope: replay.scope.clone(),
            next: crate::decision::ReplayFact {
                scope: replay.scope.clone(),
                fingerprint: replay.fingerprint,
                expires_ms: replay.expires_ms,
                state: ReplayState::Committed(TerminalResult::Applied(
                    refs.iter()
                        .map(|effect| RefValue {
                            name: effect.name.clone(),
                            value: effect.target,
                        })
                        .collect(),
                )),
            },
        });
        Ok(WriteDecision::Apply(AcceptanceEffects {
            refs,
            replay,
            membership: Vec::new(),
            tickets: Vec::new(),
            reservations: Vec::new(),
            reservation_transitions: Vec::new(),
            publication: Vec::new(),
            accounting: Vec::new(),
            storage: Vec::new(),
            outcomes: Vec::new(),
        }))
    }
}

fn target(observed: &Observed<Hash>) -> Option<Hash> {
    match observed {
        Observed::Absent(_) => None,
        Observed::Present { value, .. } => Some(*value),
    }
}
