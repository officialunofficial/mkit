//! Core types to `mkit.server.hooks.v1` messages, and hook answers back to
//! core decisions (SPEC-SERVER §§6.2, 6.3, 6.5).

use buffa::EnumValue;
use mkit_core::refs::RefWriteCondition;
use zeroize::Zeroize;

use super::proto::v1 as pb;
use super::proto::v1::__buffa::oneof as one;
use crate::error::ServerError;
use crate::op::{CallerView, OpKind, Operation, RefUpdate};
use crate::pipeline::{AdmissionDecision, AdmissionInput, Challenge, Outcome, OutcomeKind};
use crate::principal::Principal;
use crate::repo::NamespaceKey;
use crate::store::codec::AbortReason;

/// The longest public deny text (SPEC-SERVER §6.2).
const MAX_PUBLIC_TEXT: usize = 512;

fn principal(principal: &Principal) -> pb::Principal {
    let key = |k: &[u8; 32]| Some(k.to_vec());
    let kind = match principal {
        Principal::Anonymous => one::principal::Kind::from(pb::Anonymous::default()),
        Principal::Signer { ed25519 } => pb::Signer {
            ed25519_public_key: key(ed25519),
            ..Default::default()
        }
        .into(),
        Principal::BearerHolder => pb::BearerHolder::default().into(),
        Principal::TransportPeer { ed25519 } => pb::TransportPeer {
            ed25519_public_key: key(ed25519),
            ..Default::default()
        }
        .into(),
        Principal::SshForcedCommand { key: peer } => pb::SshForcedCommand {
            // §6.2: an unknown key is sent as explicit empty bytes.
            ed25519_public_key: Some(peer.as_ref().map_or_else(Vec::new, |k| k.to_vec())),
            ..Default::default()
        }
        .into(),
    };
    pb::Principal {
        kind: Some(kind),
        ..Default::default()
    }
}

fn ref_change(update: &RefUpdate) -> pb::RefChange {
    let condition = match &update.condition {
        RefWriteCondition::Any => one::ref_change::Condition::from(pb::Unconditional::default()),
        RefWriteCondition::Missing => pb::MustNotExist::default().into(),
        RefWriteCondition::Match(id) => one::ref_change::Condition::Expected(id.to_vec()),
    };
    pb::RefChange {
        name: Some(update.name.clone()),
        condition: Some(condition),
        new: update.new.map(|id| id.to_vec()),
        delete: Some(update.new.is_none()),
        ..Default::default()
    }
}

/// The wire identity the hook sees: `<namespace>/<name>`, or the bare name in
/// a single-repository deployment.
fn repository(op: &Operation) -> String {
    if op.repo.namespace == NamespaceKey::deployment_default() {
        op.repo.name.as_str().to_owned()
    } else {
        format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str())
    }
}

fn operation(op: &Operation, audience: &str) -> pb::Operation {
    let refs = match &op.kind {
        OpKind::UpdateRef(head) => vec![ref_change(head)],
        OpKind::AdvanceRefs { head, packmap, .. } => vec![ref_change(head), ref_change(packmap)],
        _ => Vec::new(),
    };
    pb::Operation {
        audience: Some(audience.to_owned()),
        repository: Some(repository(op)),
        procedure: Some(op.procedure().connect_path().to_owned()),
        principal: principal(&op.principal).into(),
        // SPEC-SERVER §6.2: the replay nonce is the idempotency key of a write
        // and empty otherwise.
        idempotency_key: op
            .procedure()
            .is_write()
            .then(|| op.auth.as_ref().map(|auth| auth.nonce.clone()))
            .flatten(),
        refs,
        owner: Some(op.authz.owner),
        grant: op
            .authz
            .grant
            .as_ref()
            .map(|grant| pb::GrantUsed {
                grant_id: Some(grant.id.to_vec()),
                epoch: Some(grant.epoch),
                ..Default::default()
            })
            .into(),
        ..Default::default()
    }
}

pub(super) fn authorize_request(op: &Operation, audience: &str) -> pb::AuthorizeRequest {
    pb::AuthorizeRequest {
        operation: operation(op, audience).into(),
        ..Default::default()
    }
}

pub(super) fn admit_request(input: &AdmissionInput<'_>, audience: &str) -> pb::AdmitRequest {
    pb::AdmitRequest {
        operation: operation(input.op, audience).into(),
        declared_bytes: Some(input.declared_bytes),
        pack_id: input.pack_id.map(|key| key.0.to_vec()),
        creates_namespace: Some(input.creates_namespace),
        creates_repo: Some(input.creates_repo),
        new_to_repo_bytes: input.new_to_repo_bytes,
        credential_headers: input
            .credential_headers
            .iter()
            .map(|header| pb::Header {
                name: Some(header.name.clone()),
                value: Some(header.value.expose().to_owned()),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

/// Wipe the admission credentials a request holds; call once it is sent.
pub(super) fn wipe(request: &mut pb::AdmitRequest) {
    for header in &mut request.credential_headers {
        if let Some(value) = header.value.as_mut() {
            value.zeroize();
        }
    }
}

fn abort_reason(reason: AbortReason) -> pb::AbortReason {
    match reason {
        AbortReason::Unspecified => pb::AbortReason::ABORT_REASON_UNSPECIFIED,
        AbortReason::RefConflict => pb::AbortReason::ABORT_REASON_REF_CONFLICT,
        AbortReason::EpochMismatch => pb::AbortReason::ABORT_REASON_EPOCH_MISMATCH,
        AbortReason::PackMissing => pb::AbortReason::ABORT_REASON_PACK_MISSING,
        AbortReason::ReplayRace => pb::AbortReason::ABORT_REASON_REPLAY_RACE,
        AbortReason::Internal => pb::AbortReason::ABORT_REASON_INTERNAL,
        AbortReason::Abandoned => pb::AbortReason::ABORT_REASON_ABANDONED,
    }
}

pub(super) fn outcome_request(outcome: &Outcome) -> pb::OutcomeRequest {
    let kind = match &outcome.kind {
        OutcomeKind::Committed {
            bytes_stored,
            new_to_repo,
            new_to_store,
            refs,
        } => pb::Committed {
            bytes_stored: Some(*bytes_stored),
            new_to_repo: Some(*new_to_repo),
            new_to_store: Some(*new_to_store),
            refs: refs
                .iter()
                .map(|r| pb::CommittedRef {
                    name: Some(r.name.clone()),
                    new: r.new.map(|id| id.to_vec()),
                    deleted: Some(r.deleted),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
        .into(),
        OutcomeKind::Aborted { reason, detail } => pb::Aborted {
            reason: Some(EnumValue::from(abort_reason(*reason))),
            detail: Some(detail.clone()),
            ..Default::default()
        }
        .into(),
        OutcomeKind::Expired => pb::Expired::default().into(),
        OutcomeKind::ReadServed {
            object,
            bytes_served,
        } => pb::ReadServed {
            object: Some(object.to_vec()),
            bytes_served: Some(*bytes_served),
            ..Default::default()
        }
        .into(),
    };
    pb::OutcomeRequest {
        outcome: pb::Outcome {
            reservation_id: Some(outcome.reservation_id.clone()),
            audience: Some(outcome.audience.clone()),
            repository: Some(outcome.repository.clone()),
            occurred_unix_ms: Some(outcome.occurred_unix_ms),
            kind: Some(kind),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

/// A hook answer that fails §6.6 or omits its decision: fail closed.
pub(super) fn unavailable(what: &'static str, reason: &'static str) -> ServerError {
    tracing::warn!(reason, "remote {what} hook unusable");
    ServerError::unavailable(format!("{what} unavailable"))
}

/// A deny message safe to show a client, or `generic`.
fn public_text(message: Option<String>, generic: &'static str) -> String {
    match message {
        Some(text)
            if !text.is_empty()
                && text.len() <= MAX_PUBLIC_TEXT
                && !text.chars().any(char::is_control) =>
        {
            text
        }
        _ => generic.to_owned(),
    }
}

/// An Authorize answer as the facts to proceed with, or the deliberate denial.
/// Only `permission_denied`, `unauthenticated` and, on a read, `not_found`
/// are honoured; every other code answers `permission_denied`.
pub(super) fn authorize_answer(
    response: pb::AuthorizeResponse,
    op: &Operation,
) -> Result<crate::op::AuthzFacts, ServerError> {
    match response.result {
        // The established owner/grant facts pass through unchanged; an
        // `authority` hook's `writer_view` classifies the caller (§10.1). The
        // pipeline honours it only under the `authority` role, so a `check`
        // hook cannot confer writer status.
        Some(one::authorize_response::Result::Allow(allow)) => {
            let mut facts = op.authz.clone();
            facts.authority_generation = allow.authority_generation;
            if allow.writer_view == Some(true) {
                facts.caller_view = CallerView::Writer;
            }
            Ok(facts)
        }
        Some(one::authorize_response::Result::Deny(deny)) => {
            let message = public_text(deny.message, "permission denied");
            Err(match deny.code.as_deref() {
                Some("unauthenticated") => ServerError::unauthenticated(message),
                Some("not_found") if !op.procedure().is_write() => ServerError::not_found(message),
                _ => ServerError::permission_denied(message),
            })
        }
        None => Err(unavailable("authorization", "absent decision")),
    }
}

fn headers(list: Vec<pb::Header>) -> Option<Vec<(String, String)>> {
    list.into_iter()
        .map(|h| Some((h.name?, h.value?)))
        .collect()
}

/// An Admit answer as a decision. It is not yet validated: the caller runs
/// [`validate_decision`](crate::pipeline::validate_decision) on it.
pub(super) fn admit_answer(response: pb::AdmitResponse) -> Result<AdmissionDecision, ServerError> {
    let bad = |reason| unavailable("admission", reason);
    Ok(
        match response.decision.ok_or_else(|| bad("absent decision"))? {
            one::admit_response::Decision::Allow(allow) => {
                let allow = *allow;
                // A remote allow must name its reservation (§6.3, §6.6); the
                // default admission is the only Allow without one.
                let id = allow
                    .reservation_id
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| bad("allow without a reservation id"))?;
                let mut decision = AdmissionDecision::allow(Vec::new()).with_reservation(id);
                for (name, value) in
                    headers(allow.response_headers).ok_or_else(|| bad("bad header"))?
                {
                    decision = decision.with_response_header(name, value);
                }
                match allow.external_ref.filter(|r| !r.is_empty()) {
                    Some(reference) => decision.with_external_ref(reference),
                    None => decision,
                }
            }
            one::admit_response::Decision::Challenge(challenge) => {
                let challenge = *challenge;
                let list = challenge
                    .challenges
                    .into_iter()
                    .map(|c| {
                        Some(Challenge {
                            scheme: c.scheme?,
                            value: c.value?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| bad("bad challenge"))?;
                let mut decision =
                    AdmissionDecision::challenge(list, challenge.description.unwrap_or_default());
                for (name, value) in
                    headers(challenge.response_headers).ok_or_else(|| bad("bad header"))?
                {
                    decision = decision.with_response_header(name, value);
                }
                decision
            }
            // Whatever `code` says, an admission denial is `permission_denied`.
            one::admit_response::Decision::Deny(deny) => {
                AdmissionDecision::deny(public_text(deny.message, "admission denied"))
            }
        },
    )
}
