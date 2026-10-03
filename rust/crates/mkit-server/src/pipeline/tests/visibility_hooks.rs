//! `SetRepoVisibility` runs admission before it writes and records an
//! outcome after it commits, in both modes (SPEC-SERVER §6.3, §6.5).

use super::grants::{config, repository};
use super::visibility::{
    put_repo, repo_id, set, signed_visibility, statement, stored_visibility_row,
    unsigned_visibility,
};
use super::*;
use crate::pipeline::{DeliveryError, Outcome, OutcomeKind, OutcomeSink};
use crate::quota::QuotaLimits;
use crate::telemetry::NoopMetrics;
use crate::timers::outcome_delivery::OutcomeDelivery;
use crate::timers::{TickBudget, TimerRegistry, run_due};
use mkit_attest::grant::Visibility;

/// What admission saw of a visibility change.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    procedure: Procedure,
    visibility: Option<Visibility>,
    declared_bytes: u64,
    pack_id: Option<PackKey>,
    signed: bool,
    idempotency_key: Option<String>,
    owner: bool,
}

/// Records every input and answers with a fixed decision.
struct Scripted {
    seen: Mutex<Vec<Seen>>,
    decision: AdmissionDecision,
}

impl Scripted {
    fn new(decision: AdmissionDecision) -> Self {
        Self {
            seen: Mutex::default(),
            decision,
        }
    }
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Admission for Scripted {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        self.seen.lock().unwrap().push(Seen {
            procedure: input.op.procedure(),
            visibility: match &input.op.kind {
                OpKind::SetRepoVisibility { visibility } => Some(*visibility),
                _ => None,
            },
            declared_bytes: input.declared_bytes,
            pack_id: input.pack_id,
            signed: input.op.auth.is_some(),
            idempotency_key: input.idempotency_key.map(str::to_owned),
            owner: input.op.authz.owner,
        });
        Ok(self.decision.clone())
    }
}

fn env_with(
    owner: &SigningKey,
    decision: AdmissionDecision,
) -> Env<Hooks<OpenAuthorizer, Scripted>> {
    let clock = clock();
    build(
        config(owner, AuthorizerRole::Check),
        Spy::new(store(&clock)),
        with_admission(Scripted::new(decision)),
        clock,
    )
}

fn allow() -> AdmissionDecision {
    AdmissionDecision::allow(Vec::new())
}

fn reserved(rid: &str) -> AdmissionDecision {
    allow().with_reservation(rid)
}

fn coordinator<H: HookSet>(e: &Env<H>, owner: &SigningKey) -> Partition {
    e.pipe.shards.coordinator(&repo_id(e, owner).namespace)
}

fn get<H: HookSet>(e: &Env<H>, p: &Partition, key: &Key) -> Option<Value> {
    now(e.pipe.meta.inner.get(p, key)).unwrap()
}

/// The terminal row and index marker of reservation `rid`, as delivery
/// decodes them.
fn delivered<H: HookSet>(e: &Env<H>, owner: &SigningKey, rid: &str) -> Outcome {
    let p = coordinator(e, owner);
    let row = get(e, &p, &keys::reservation(rid).unwrap()).expect("reservation row");
    let (start, end) = keys::class_range(keys::TAG_OUTCOME_PENDING);
    let page = now(e.pipe.meta.inner.scan(&p, &start, &end, None, 100)).unwrap();
    let [(_, marker)] = page.entries.as_slice() else {
        panic!("one queued outcome, got {}", page.entries.len());
    };
    Outcome::from_reservation(
        rid.to_owned(),
        AUDIENCE.to_owned(),
        codec::decode_reservation(&row).unwrap(),
    )
    .unwrap()
    .with_marker(marker.as_bytes())
}

fn assert_nothing_written<H: HookSet>(e: &Env<H>, owner: &SigningKey) {
    assert!(e.pipe.meta.batches.lock().unwrap().is_empty());
    let p = coordinator(e, owner);
    assert_eq!(now(e.pipe.meta.inner.stats(&p)).unwrap().keys, Some(0));
}

#[test]
fn admission_sees_the_visibility_operation_in_both_modes() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(&owner, allow());
    set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    let (stmt, _) = statement(&owner, &repo, Visibility::Public, T0 + 1_000, [1; 32]);
    set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(stmt),
    )
    .unwrap();
    let base = Seen {
        procedure: Procedure::SetRepoVisibility,
        visibility: Some(Visibility::Private),
        declared_bytes: 0,
        pack_id: None,
        signed: true,
        idempotency_key: Some(nonce(1)),
        owner: true,
    };
    assert_eq!(
        e.pipe.hooks.admission.seen(),
        vec![
            base.clone(),
            Seen {
                visibility: Some(Visibility::Public),
                signed: false,
                idempotency_key: None,
                ..base
            }
        ]
    );
}

#[test]
fn an_envelope_replay_never_reaches_admission() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(&owner, allow());
    let req = signed_visibility(&owner, &repo, 1, b"v");
    set(&e, &req, VisibilityRequest::Envelope(Visibility::Private)).unwrap();
    set(&e, &req, VisibilityRequest::Envelope(Visibility::Private)).unwrap();
    assert_eq!(e.pipe.hooks.admission.seen().len(), 1);
}

#[test]
fn an_admission_refusal_blocks_both_modes_without_a_state_change() {
    let owner = key(1);
    let repo = repository(&owner);
    for decision in [
        AdmissionDecision::deny("closed"),
        AdmissionDecision::Deny(ServerError::permission_denied("closed")),
    ] {
        let e = env_with(&owner, decision);
        let err = set(
            &e,
            &signed_visibility(&owner, &repo, 1, b"v"),
            VisibilityRequest::Envelope(Visibility::Private),
        )
        .unwrap_err();
        assert_eq!(
            (err.code(), err.public_message(), err.http_status()),
            (Code::PermissionDenied, "closed", Some(403))
        );
        assert_nothing_written(&e, &owner);
        let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [1; 32]);
        let err = set(
            &e,
            &unsigned_visibility(&repo),
            VisibilityRequest::Statement(stmt),
        )
        .unwrap_err();
        assert_eq!(
            (err.code(), err.public_message(), err.http_status()),
            (Code::PermissionDenied, "closed", Some(403))
        );
        assert_nothing_written(&e, &owner);
        assert_eq!(e.pipe.hooks.admission.seen().len(), 2);
    }
}

#[test]
fn an_admission_challenge_propagates_in_both_modes_without_a_state_change() {
    let owner = key(1);
    let repo = repository(&owner);
    let challenge = AdmissionDecision::challenge(
        vec![Challenge {
            scheme: "mpp".into(),
            value: "id=1".into(),
        }],
        "pay",
    );
    let e = env_with(&owner, challenge);
    let envelope = set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [1; 32]);
    let statement = set(
        &e,
        &unsigned_visibility(&repo),
        VisibilityRequest::Statement(stmt),
    )
    .unwrap_err();
    for err in [envelope, statement] {
        assert_eq!(
            (err.code(), err.public_message(), err.http_status()),
            (Code::PermissionDenied, "admission required", Some(402))
        );
        assert!(!err.details().is_empty());
    }
    assert_nothing_written(&e, &owner);
}

#[test]
fn a_visibility_change_charges_no_quota_even_when_the_quota_is_spent() {
    let owner = key(1);
    let repo = repository(&owner);
    let clock = clock();
    let mut cfg = config(&owner, AuthorizerRole::Check);
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 0,
        max_bytes: 0,
    });
    // DefaultAdmission would exhaust a write that it charges.
    let e = build(
        cfg,
        Spy::new(store(&clock)),
        with_admission(DefaultAdmission),
        clock,
    );
    let id = repo_id(&e, &owner);
    set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    assert_eq!(
        stored_visibility_row(&e, &id).visibility,
        codec::StoredVisibility::Private
    );
    let p = coordinator(&e, &owner);
    let (start, end) = keys::class_range(keys::TAG_QUOTA);
    assert!(
        now(e.pipe.meta.inner.scan(&p, &start, &end, None, 10))
            .unwrap()
            .entries
            .is_empty()
    );
}

#[test]
fn default_admission_charges_no_bytes_and_no_operation_for_a_visibility_change() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(&owner, allow());
    let a = e.auth(&signed_visibility(&owner, &repo, 1, b"v")).unwrap();
    let op = e
        .pipe
        .identify(
            &a,
            OpKind::SetRepoVisibility {
                visibility: Visibility::Private,
            },
        )
        .unwrap();
    let mut input = AdmissionInput::new(&op);
    input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
    let AdmissionDecision::Allow { charges, .. } =
        block_on(DefaultAdmission.admit(&input)).unwrap()
    else {
        panic!("default admission allows");
    };
    assert!(charges.is_empty());
}

#[test]
fn both_modes_record_a_committed_outcome_that_names_the_visibility_change() {
    let owner = key(1);
    let repo = repository(&owner);
    for (mode, rid) in [("envelope", "env-rid"), ("statement", "stmt-rid")] {
        let e = env_with(&owner, reserved(rid));
        if mode == "envelope" {
            set(
                &e,
                &signed_visibility(&owner, &repo, 1, b"v"),
                VisibilityRequest::Envelope(Visibility::Private),
            )
            .unwrap();
        } else {
            let (stmt, _) = statement(&owner, &repo, Visibility::Private, T0, [1; 32]);
            set(
                &e,
                &unsigned_visibility(&repo),
                VisibilityRequest::Statement(stmt),
            )
            .unwrap();
        }
        let outcome = delivered(&e, &owner, rid);
        assert_eq!(
            outcome.procedure,
            Some(Procedure::SetRepoVisibility),
            "{mode}"
        );
        assert_eq!(outcome.visibility, Some(Visibility::Private), "{mode}");
        assert!(
            matches!(
                &outcome.kind,
                OutcomeKind::Committed { bytes_stored: 0, new_to_repo: 0, new_to_store: 0, refs }
                    if refs.is_empty()
            ),
            "{mode}: {:?}",
            outcome.kind
        );
        // The pending row and the change commit together: the backlog holds
        // exactly this outcome.
        let p = coordinator(&e, &owner);
        let backlog = get(&e, &p, &keys::outcome_backlog()).unwrap();
        assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1, "{mode}");
    }
}

/// Collects delivered outcomes.
#[derive(Default)]
struct Capture(Mutex<Vec<Outcome>>);

impl OutcomeSink for Capture {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        self.0.lock().unwrap().push(outcome.clone());
        Ok(())
    }
}

#[test]
fn the_outcome_sink_receives_the_visibility_outcome_through_the_delivery_timer() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(&owner, reserved("env-rid"));
    set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Public),
    )
    .unwrap();
    let sink = Arc::new(Capture::default());
    let registry = TimerRegistry::new().register(OutcomeDelivery::new(
        sink.clone(),
        AUDIENCE.into(),
        Arc::new(NoopMetrics),
        Arc::new(crate::rt::ManualSleep::new()),
    ));
    let p = coordinator(&e, &owner);
    let report = now(run_due(
        e.pipe.meta.inner.as_ref(),
        &p,
        &registry,
        e.clock.as_ref(),
        u64::try_from(T0).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
    assert_eq!(report.fired, 1);
    let seen = sink.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].reservation_id, "env-rid");
    assert_eq!(seen[0].procedure, Some(Procedure::SetRepoVisibility));
    assert_eq!(seen[0].visibility, Some(Visibility::Public));
    // Acknowledged: the queue and backlog drained despite the marker value.
    assert_eq!(
        now(e.pipe.meta.inner.scan(
            &p,
            &keys::class_range(keys::TAG_OUTCOME_PENDING).0,
            &keys::class_range(keys::TAG_OUTCOME_PENDING).1,
            None,
            10
        ))
        .unwrap()
        .entries
        .len(),
        0
    );
}

#[test]
fn a_failed_reserved_visibility_change_aborts_with_the_visibility_marker() {
    let owner = key(1);
    let repo = repository(&owner);
    let current = clock();
    let mut spy = Spy::new(store(&current));
    let fail = spy.fail_next_apply.clone();
    spy.after_hook = Some(Box::new(move |_, _, batch, result| {
        let pending = batch.writes.iter().any(|write| matches!(write,
            Write::Put(_, value) if matches!(codec::decode_reservation(value), Ok(codec::ReservationV1::Pending { .. }))));
        if pending && matches!(result, BatchOutcome::Committed) {
            fail.store(true, Ordering::SeqCst);
        }
    }));
    let e = build(
        config(&owner, AuthorizerRole::Check),
        spy,
        with_admission(Scripted::new(reserved("abort-rid"))),
        current,
    );
    let err = set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    let outcome = delivered(&e, &owner, "abort-rid");
    assert!(matches!(
        outcome.kind,
        OutcomeKind::Aborted {
            reason: codec::AbortReason::Internal,
            ..
        }
    ));
    assert_eq!(outcome.procedure, Some(Procedure::SetRepoVisibility));
    assert_eq!(outcome.visibility, Some(Visibility::Private));
    // The change itself did not land.
    let p = coordinator(&e, &owner);
    let id = repo_id(&e, &owner);
    assert!(get(&e, &p, &keys::repo_visibility(&id.name)).is_none());
}

#[test]
fn the_receipt_headers_of_a_committed_change_reach_the_caller_once() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(
        &owner,
        allow().with_response_header("Payment-Receipt", "receipt"),
    );
    let req = signed_visibility(&owner, &repo, 1, b"v");
    let meta = block_on(e.pipe.set_repo_visibility_with_meta(
        &e.auth(&req).unwrap(),
        VisibilityRequest::Envelope(Visibility::Private),
    ))
    .unwrap();
    assert!(
        meta.headers()
            .iter()
            .any(|(name, value)| name == "Payment-Receipt" && value == "receipt")
    );
    // A replay carries no receipt.
    let meta = block_on(e.pipe.set_repo_visibility_with_meta(
        &e.auth(&req).unwrap(),
        VisibilityRequest::Envelope(Visibility::Private),
    ))
    .unwrap();
    assert!(meta.headers().is_empty());
}

#[test]
fn a_visibility_outcome_without_a_reservation_queues_nothing() {
    let owner = key(1);
    let repo = repository(&owner);
    let e = env_with(&owner, allow());
    let id = repo_id(&e, &owner);
    put_repo(&e, &id, None);
    set(
        &e,
        &signed_visibility(&owner, &repo, 1, b"v"),
        VisibilityRequest::Envelope(Visibility::Private),
    )
    .unwrap();
    let p = coordinator(&e, &owner);
    let (start, end) = keys::class_range(keys::TAG_OUTCOME_PENDING);
    assert!(
        now(e.pipe.meta.inner.scan(&p, &start, &end, None, 10))
            .unwrap()
            .entries
            .is_empty()
    );
}
