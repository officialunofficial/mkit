//! Ref admissions bind the effects applied and settle separately from upload bytes.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail immediately.

use super::indexed::{environment_with_hooks, pack, signed, upload};
use super::*;
use mkit_core::transfer::encode_packlist;

#[derive(Default)]
struct Calls(Mutex<Vec<(Procedure, u64)>>);
impl Admission for Calls {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        self.0
            .lock()
            .unwrap()
            .push((input.op.procedure(), input.declared_bytes));
        Ok(AdmissionDecision::allow(Vec::new()))
    }
}

fn begin<H: HookSet>(
    env: &Env<H>,
    owner: &SigningKey,
    identity: &str,
    bytes: &[u8],
    n: u32,
) -> Hash {
    let request = signed(owner, identity, Procedure::BeginUpload, n);
    let BeginUploadResult::Ticket { id, .. } = now(env.pipe.begin_upload(
        &env.auth(&request).unwrap(),
        HEAD,
        &hash(bytes),
        bytes.len() as u64,
    ))
    .unwrap() else {
        panic!("expected ticket")
    };
    upload(env, bytes, id);
    id
}

#[test]
fn ticketed_advance_calls_ref_admission_without_recharging_pack_bytes() {
    let (env, owner, identity) = environment_with_hooks(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
        None,
        with_admission(Calls::default()),
    );
    let (bytes, head) = pack();
    let node = encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        begin(&env, &owner, &identity, &bytes, 1),
        begin(&env, &owner, &identity, &node, 2),
    ];
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 3);
    now(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(&node)),
        tickets,
    ))
    .unwrap();
    assert_eq!(
        *env.pipe.hooks.admission.0.lock().unwrap(),
        vec![
            (Procedure::BeginUpload, bytes.len() as u64),
            (Procedure::BeginUpload, node.len() as u64),
            (Procedure::AdvanceRefs, 0),
        ]
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    procedure: Procedure,
    bytes: u64,
    updates: Vec<ResolvedRefUpdate>,
    request_condition: Option<RefWriteCondition>,
}

#[derive(Default)]
struct Effects(Mutex<Vec<Seen>>);
impl Admission for Effects {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let mut seen = self.0.lock().unwrap();
        let rid = format!("effects-{}", seen.len());
        seen.push(Seen {
            procedure: input.op.procedure(),
            bytes: input.declared_bytes,
            updates: input.resolved_ref_updates.clone(),
            request_condition: match &input.op.kind {
                OpKind::UpdateRef(update) => Some(update.condition),
                _ => None,
            },
        });
        Ok(AdmissionDecision::allow(Vec::new()).with_reservation(rid))
    }
}

fn resolved(name: &str, new: Option<Hash>, effect: RefEffect) -> ResolvedRefUpdate {
    ResolvedRefUpdate {
        name: name.into(),
        new,
        effect,
    }
}

fn reservation<H: HookSet>(env: &Env<H>, partition: &Partition, rid: &str) -> codec::ReservationV1 {
    codec::decode_reservation(
        &now(env
            .pipe
            .meta
            .get(partition, &keys::reservation(rid).unwrap()))
        .unwrap()
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn explicit_ref_effects_and_outcomes_cover_create_replace_delete_and_absent_delete() {
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(Effects::default()),
        clock,
    );
    let owner = key(7);
    let updates = [
        upd(HEAD, Missing, A),
        upd(HEAD, Match(A), B),
        RefUpdate {
            name: HEAD.into(),
            condition: Match(B),
            new: None,
        },
        RefUpdate {
            name: HEAD.into(),
            condition: Match(B),
            new: None,
        },
    ];
    for (n, update) in updates.iter().enumerate() {
        let result = env
            .update(
                &Req::update(&owner, u32::try_from(n).unwrap() + 1, update, T0),
                update,
            )
            .unwrap();
        assert_eq!(
            result,
            if n == 3 {
                UpdateRefResult::Conflict { current: None }
            } else {
                UpdateRefResult::Committed
            }
        );
    }
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(
        seen.iter().map(|s| s.updates.clone()).collect::<Vec<_>>(),
        vec![
            vec![resolved(HEAD, Some(A), RefEffect::Create)],
            vec![resolved(HEAD, Some(B), RefEffect::Replace)],
            vec![resolved(HEAD, None, RefEffect::Delete)],
            vec![resolved(HEAD, None, RefEffect::Delete)],
        ]
    );
    for rid in ["effects-0", "effects-1", "effects-2"] {
        assert!(matches!(
            reservation(&env, &ns(), rid),
            codec::ReservationV1::Committed { .. }
        ));
    }
    assert!(matches!(
        reservation(&env, &ns(), "effects-3"),
        codec::ReservationV1::Aborted { .. }
    ));
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn custom_admission_rejects_duplicate_ref_creates_and_deletes_before_reserving() {
    for deleting in [false, true] {
        let clock = clock();
        let env = build(
            cfg(authv2()),
            Spy::new(store(&clock)),
            with_admission(Effects::default()),
            clock,
        );
        if deleting {
            seed(&env.pipe.meta.inner, &[(HEAD, A)]);
        }
        let before = env.rows();
        let update = RefUpdate {
            name: HEAD.into(),
            condition: if deleting { Match(A) } else { Missing },
            new: if deleting { None } else { Some(B) },
        };
        let req = Req::signed(&key(7), Procedure::AdvanceRefs, b"duplicate", &nonce(1), T0);
        let error = env.advance(&req, &update, &update).unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(env.pipe.hooks.admission.0.lock().unwrap().is_empty());
        assert!(env.batches().is_empty());
        assert_eq!(
            env.rows(),
            before,
            "no ref, replay, quota, or reservation changes"
        );
    }
}

#[test]
fn default_admission_preserves_duplicate_ref_creates_and_deletes() {
    let env = env(AuthMode::Open);
    let create = upd(HEAD, Missing, A);
    assert_eq!(
        env.advance(&Req::unsigned(Procedure::AdvanceRefs), &create, &create)
            .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.read(HEAD), Some(A));
    let delete = RefUpdate {
        name: HEAD.into(),
        condition: Match(A),
        new: None,
    };
    assert_eq!(
        env.advance(&Req::unsigned(Procedure::AdvanceRefs), &delete, &delete)
            .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn ticketless_advance_admits_both_ref_effects() {
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(Effects::default()),
        clock,
    );
    let owner = key(7);
    let req = Req::signed(&owner, Procedure::AdvanceRefs, b"advance", &nonce(1), T0);
    env.advance(&req, &upd(HEAD, Missing, A), &upd(PACKMAP, Missing, B))
        .unwrap();
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(
        seen[0].updates,
        vec![
            resolved(PACKMAP, Some(B), RefEffect::Create),
            resolved(HEAD, Some(A), RefEffect::Create)
        ]
    );
    assert_eq!(seen[0].bytes, 0);
}

#[test]
fn ticketed_pack_and_ref_reservations_commit_in_the_same_batch() {
    let (env, owner, identity) = environment_with_hooks(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
        None,
        with_admission(Effects::default()),
    );
    let (bytes, head) = pack();
    let node = encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        begin(&env, &owner, &identity, &bytes, 1),
        begin(&env, &owner, &identity, &node, 2),
    ];
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 3))
        .unwrap();
    now(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(&node)),
        tickets,
    ))
    .unwrap();
    let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[2].procedure, Procedure::AdvanceRefs);
    assert!(seen[0].updates.is_empty() && seen[1].updates.is_empty());
    assert_eq!(
        seen[2].updates,
        vec![
            resolved(PACKMAP, Some(hash(&node)), RefEffect::Create),
            resolved(HEAD, Some(head), RefEffect::Create)
        ]
    );
    assert_eq!(seen[2].bytes, 0);
    for rid in ["effects-0", "effects-1", "effects-2"] {
        assert!(matches!(
            reservation(&env, &partition, rid),
            codec::ReservationV1::Committed { .. }
        ));
    }
    let ref_outcome = reservation(&env, &partition, "effects-2");
    assert!(matches!(
        ref_outcome,
        codec::ReservationV1::Committed {
            bytes_stored: 0,
            new_to_repo: 0,
            new_to_store: 0,
            ..
        }
    ));
    let pack_bytes: u64 = ["effects-0", "effects-1"]
        .iter()
        .map(|rid| match reservation(&env, &partition, rid) {
            codec::ReservationV1::Committed { bytes_stored, .. } => bytes_stored,
            _ => panic!("expected committed pack reservation"),
        })
        .sum();
    assert_eq!(pack_bytes, (bytes.len() + node.len()) as u64);
    assert!(env.batches().iter().any(|batch| ["effects-0", "effects-1", "effects-2"].iter().all(|rid| batch.writes.iter().any(|w| matches!(w, Write::Put(k, v) if *k == keys::reservation(rid).unwrap() && matches!(codec::decode_reservation(v), Ok(codec::ReservationV1::Committed { .. })))))));
}

struct CapOne(AtomicBool);
impl Admission for CapOne {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        assert_eq!(input.resolved_ref_updates.len(), 1);
        assert_eq!(input.resolved_ref_updates[0].effect, RefEffect::Create);
        if self.0.swap(true, Ordering::SeqCst) {
            return Ok(AdmissionDecision::Deny(ServerError::permission_denied(
                "ref cap",
            )));
        }
        YieldOnce::default().await;
        Ok(AdmissionDecision::allow(Vec::new()).with_reservation("cap-slot"))
    }
}

#[test]
fn concurrent_different_ref_creates_reserve_only_one_slot() {
    let clock = clock();
    let meta = Spy::new(store(&clock));
    let env = build(
        cfg(authv2()),
        meta,
        with_admission(CapOne(AtomicBool::new(false))),
        clock,
    );
    let one = upd("refs/heads/one", Missing, A);
    let two = upd("refs/heads/two", Missing, B);
    let a = env.auth(&Req::update(&key(7), 1, &one, T0)).unwrap();
    let b = env.auth(&Req::update(&key(7), 2, &two, T0)).unwrap();
    let (one_result, two_result) = block_on(async {
        futures::join!(env.pipe.update_ref(&a, one), env.pipe.update_ref(&b, two))
    });
    let results = [one_result, two_result];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(UpdateRefResult::Committed)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r
                .as_ref()
                .is_err_and(|e| e.code() == Code::PermissionDenied))
            .count(),
        1
    );
    assert_eq!(
        [env.read("refs/heads/one"), env.read("refs/heads/two")]
            .iter()
            .filter(|v| v.is_some())
            .count(),
        1
    );
    assert!(matches!(
        reservation(&env, &ns(), "cap-slot"),
        codec::ReservationV1::Committed { .. }
    ));
}

#[test]
fn unconditional_advance_does_not_apply_a_replanned_effect_without_admission() {
    let clock = clock();
    let raced = Arc::new(AtomicBool::new(false));
    let once = raced.clone();
    let meta = Spy::new(store(&clock)).hook(move |kv, _, batch| {
        if batch
            .writes
            .iter()
            .any(|w| matches!(w, Write::Put(k, _) if *k == keys::ref_key(&repo_name(), HEAD)))
            && !once.swap(true, Ordering::SeqCst)
        {
            seed(kv, &[(HEAD, C)]);
        }
    });
    let env = build(
        cfg(authv2()),
        meta,
        with_admission(Effects::default()),
        clock,
    );
    let req = Req::signed(&key(7), Procedure::AdvanceRefs, b"advance", &nonce(1), T0);
    let result = env.advance(&req, &upd(HEAD, Any, A), &upd(PACKMAP, Any, B));
    assert!(raced.load(Ordering::SeqCst));
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(seen[0].updates[0].effect, RefEffect::Create);
    assert_eq!(
        seen.len(),
        1,
        "changed effect must abort without re-admission"
    );
    assert!(!matches!(result, Ok(AdvanceOutcome::Committed)));
    assert_eq!(env.read(HEAD), Some(C));
    assert_eq!(env.read(PACKMAP), None);
    assert!(matches!(
        reservation(&env, &ns(), "effects-0"),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::RefConflict,
            ..
        }
    ));
}

#[test]
fn default_ticketed_advance_keeps_quota_bytes_and_operations_unchanged() {
    let (env, owner, identity) = environment_with_hooks(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
        None,
        Hooks::new(),
    );
    let (bytes, head) = pack();
    let node = encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        begin(&env, &owner, &identity, &bytes, 1),
        begin(&env, &owner, &identity, &node, 2),
    ];
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 3))
        .unwrap();
    let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    let quota_rows = || {
        let (start, end) = keys::class_range(keys::TAG_QUOTA);
        now(env
            .pipe
            .meta
            .inner
            .scan(&partition, &start, &end, None, 100))
        .unwrap()
        .entries
    };
    let before = quota_rows();
    assert!(!before.is_empty());
    let states: Vec<_> = before
        .iter()
        .map(|(_, v)| codec::decode_quota_state(v).unwrap())
        .collect();
    assert_eq!(states.iter().map(|s| s.ops).sum::<u32>(), 2);
    assert_eq!(
        states.iter().map(|s| s.bytes).sum::<u64>(),
        (bytes.len() + node.len()) as u64
    );
    now(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(&node)),
        tickets,
    ))
    .unwrap();
    assert_eq!(
        quota_rows(),
        before,
        "zero-byte ref admission must not charge another operation"
    );
}

#[cfg(feature = "ssh")]
#[test]
fn consuming_update_admits_ref_effects_without_charging_uploaded_bytes() {
    use crate::pipeline::implicit::PendingPack;
    use crate::store::{BlobKey, BlobStore, PackSink};
    use bytes::Bytes;
    use mkit_core::repo_identity::Namespace;

    let owner = key(7);
    let namespace =
        NamespaceKey::from_namespace(&Namespace::Ed25519(*owner.verifying_key().as_bytes()));
    let repo = RepoId {
        namespace,
        name: repo_name(),
    };
    let mut config = cfg(AuthMode::TransportIdentity);
    config.addressing = Addressing::Single { repo: repo.clone() };
    config.write_policy = WritePolicy::Owner;
    let clock = clock();
    let env = build(
        config,
        Spy::new(store(&clock)),
        with_admission(Effects::default()),
        clock,
    );
    let (bytes, _) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let map_id = hash(&node);
    for bytes in [&bytes, &node] {
        now(async {
            let mut sink = env
                .pipe
                .blobs
                .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
                .await
                .unwrap();
            sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
            sink.commit().await.unwrap();
        });
    }
    let mut req = Req::unsigned(Procedure::UpdateRef);
    req.principal = Some(Principal::TransportPeer {
        ed25519: *owner.verifying_key().as_bytes(),
    });
    let auth = env.auth(&req).unwrap();
    let pending = [
        PendingPack {
            pack: pack_id,
            bytes: bytes.len() as u64,
            packlist: false,
        },
        PendingPack {
            pack: map_id,
            bytes: node.len() as u64,
            packlist: true,
        },
    ];
    assert_eq!(
        now(env
            .pipe
            .update_packmap_consuming(&auth, upd(PACKMAP, Any, map_id), &pending))
        .unwrap(),
        UpdateRefResult::Committed
    );
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].updates,
        vec![resolved(PACKMAP, Some(map_id), RefEffect::Create)]
    );
    assert_eq!(seen[0].bytes, 0);
    assert_eq!(
        seen[0].request_condition,
        Some(Any),
        "admission sees the original request while effects use B10's fenced CAS"
    );
    let partition = env.pipe.shards.ref_shard(&repo, PACKMAP);
    assert!(matches!(
        reservation(&env, &partition, "effects-0"),
        codec::ReservationV1::Committed { .. }
    ));
}

struct Refusal {
    decision: AdmissionDecision,
    uploads: AtomicU32,
}
impl Admission for Refusal {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        if input.op.procedure() == Procedure::BeginUpload {
            let n = self.uploads.fetch_add(1, Ordering::SeqCst);
            Ok(AdmissionDecision::allow(Vec::new()).with_reservation(format!("upload-{n}")))
        } else {
            assert!(!input.resolved_ref_updates.is_empty());
            Ok(self.decision.clone())
        }
    }
}

#[test]
fn ticketed_ref_denial_and_challenge_keep_pack_reservations_ticketed_and_refs_absent() {
    for decision in [
        AdmissionDecision::Deny(ServerError::permission_denied("ref cap")),
        AdmissionDecision::challenge(
            vec![Challenge {
                scheme: "mpp".into(),
                value: "ref-slot".into(),
            }],
            "ref slot required",
        ),
    ] {
        let (env, owner, identity) = environment_with_hooks(
            Sharding::Single,
            crate::indexed::IndexedConfig::default(),
            None,
            with_admission(Refusal {
                decision,
                uploads: AtomicU32::new(0),
            }),
        );
        let (bytes, head) = pack();
        let node = encode_packlist(None, &[hash(&bytes)]).unwrap();
        let tickets = vec![
            begin(&env, &owner, &identity, &bytes, 1),
            begin(&env, &owner, &identity, &node, 2),
        ];
        let auth = env
            .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 3))
            .unwrap();
        let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
        let before = [
            reservation(&env, &partition, "upload-0"),
            reservation(&env, &partition, "upload-1"),
        ];
        let before_batches = env.batches().len();
        let error = now(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, hash(&node)),
            tickets,
        ))
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            env.batches().len(),
            before_batches,
            "refusal must not write verification metadata or any other batch"
        );
        for (i, rid) in ["upload-0", "upload-1"].iter().enumerate() {
            assert_eq!(reservation(&env, &partition, rid), before[i]);
            assert!(matches!(before[i], codec::ReservationV1::Ticketed { .. }));
        }
        for name in [HEAD, PACKMAP] {
            assert!(
                now(env
                    .pipe
                    .meta
                    .get(&partition, &keys::ref_key(&auth.repo().repo.name, name)))
                .unwrap()
                .is_none()
            );
        }
        for id in [hash(&bytes), hash(&node)] {
            assert!(
                now(env
                    .pipe
                    .meta
                    .get(&partition, &keys::membership(&auth.repo().repo.name, &id)))
                .unwrap()
                .is_none()
            );
        }
    }
}

#[derive(Default)]
struct Delivered(Mutex<Vec<crate::pipeline::Outcome>>);
impl OutcomeSink for Delivered {
    async fn deliver(&self, outcome: &crate::pipeline::Outcome) -> Result<(), DeliveryError> {
        self.0.lock().unwrap().push(outcome.clone());
        Ok(())
    }
}

#[test]
fn outcome_delivery_settles_committed_create_aborted_create_and_committed_delete_exactly() {
    use crate::pipeline::OutcomeKind;
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(Effects::default()),
        clock,
    );
    let owner = key(7);
    let create = upd(HEAD, Missing, A);
    assert_eq!(
        env.update(&Req::update(&owner, 1, &create, T0), &create)
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.update(&Req::update(&owner, 2, &create, T0), &create)
            .unwrap(),
        UpdateRefResult::Conflict { current: Some(A) }
    );
    let delete = RefUpdate {
        name: HEAD.into(),
        condition: Match(A),
        new: None,
    };
    assert_eq!(
        env.update(&Req::update(&owner, 3, &delete, T0), &delete)
            .unwrap(),
        UpdateRefResult::Committed
    );
    let sink = Arc::new(Delivered::default());
    let registry = crate::timers::TimerRegistry::new().register(
        crate::timers::outcome_delivery::OutcomeDelivery::new(
            sink.clone(),
            AUDIENCE.into(),
            Arc::new(crate::NoopMetrics),
            Arc::new(crate::rt::ManualSleep::new()),
        ),
    );
    now(crate::timers::run_due(
        env.pipe.meta.inner.as_ref(),
        &ns(),
        &registry,
        env.clock.as_ref(),
        u64::try_from(T0).unwrap(),
        &crate::timers::TickBudget::default(),
    ))
    .unwrap();
    let outcomes = sink.0.lock().unwrap();
    let admitted = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(outcomes.len(), 3);
    let mut count = 0i32;
    for (i, expected) in [
        (0, RefEffect::Create),
        (1, RefEffect::Create),
        (2, RefEffect::Delete),
    ] {
        assert_eq!(admitted[i].updates[0].effect, expected);
        let outcome = outcomes
            .iter()
            .find(|o| o.reservation_id == format!("effects-{i}"))
            .unwrap();
        assert_eq!(outcome.procedure, Some(Procedure::UpdateRef));
        match (&outcome.kind, expected) {
            (OutcomeKind::Committed { refs, .. }, RefEffect::Create) => {
                assert_eq!(refs.len(), 1);
                count += 1;
            }
            (OutcomeKind::Committed { refs, .. }, RefEffect::Delete) => {
                assert_eq!(refs.len(), 1);
                count -= 1;
            }
            (OutcomeKind::Aborted { .. }, RefEffect::Create) => {}
            _ => panic!("unexpected settlement"),
        }
        assert_eq!(count, i32::from(i != 2));
    }
}

#[test]
fn absent_unconditional_deletion_is_no_change_while_public_validation_stays_unchanged() {
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(Effects::default()),
        clock,
    );
    let delete = RefUpdate {
        name: HEAD.into(),
        condition: Any,
        new: None,
    };
    let auth = env.auth(&Req::update(&key(7), 1, &delete, T0)).unwrap();
    assert_eq!(
        now(env.pipe.update_ref(&auth, delete.clone()))
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(env.pipe.hooks.admission.0.lock().unwrap().is_empty());
    let result = now(env.pipe.write_with(&auth, OpKind::UpdateRef(delete), None)).unwrap();
    assert!(matches!(
        result.0,
        StoredResult::UpdateRef(UpdateRefResult::Committed)
    ));
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(
        seen[0].updates,
        vec![resolved(HEAD, None, RefEffect::NoChange)]
    );
    assert!(matches!(
        reservation(&env, &ns(), "effects-0"),
        codec::ReservationV1::Committed { .. }
    ));
    assert_eq!(env.read(HEAD), None);
}

#[cfg(feature = "ssh")]
#[test]
fn consuming_update_refusal_and_challenge_create_neither_refs_nor_membership() {
    use crate::pipeline::implicit::PendingPack;
    use crate::store::{BlobKey, BlobStore, PackSink};
    use bytes::Bytes;
    use mkit_core::repo_identity::Namespace;
    for decision in [
        AdmissionDecision::Deny(ServerError::permission_denied("ref cap")),
        AdmissionDecision::challenge(
            vec![Challenge {
                scheme: "mpp".into(),
                value: "ref-slot".into(),
            }],
            "ref slot required",
        ),
    ] {
        let owner = key(7);
        let repo = RepoId {
            namespace: NamespaceKey::from_namespace(&Namespace::Ed25519(
                *owner.verifying_key().as_bytes(),
            )),
            name: repo_name(),
        };
        let mut config = cfg(AuthMode::TransportIdentity);
        config.addressing = Addressing::Single { repo: repo.clone() };
        config.write_policy = WritePolicy::Owner;
        let clock = clock();
        let env = build(
            config,
            Spy::new(store(&clock)),
            with_admission(Refusal {
                decision,
                uploads: AtomicU32::new(0),
            }),
            clock,
        );
        let node = encode_packlist(None, &[]).unwrap();
        let map = hash(&node);
        now(async {
            let mut sink = env
                .pipe
                .blobs
                .begin(BlobKey::pack(map), node.len() as u64)
                .await
                .unwrap();
            sink.write(Bytes::copy_from_slice(&node)).await.unwrap();
            sink.commit().await.unwrap();
        });
        let mut req = Req::unsigned(Procedure::UpdateRef);
        req.principal = Some(Principal::TransportPeer {
            ed25519: *owner.verifying_key().as_bytes(),
        });
        let auth = env.auth(&req).unwrap();
        let pending = [PendingPack {
            pack: map,
            bytes: node.len() as u64,
            packlist: true,
        }];
        assert_eq!(
            now(env
                .pipe
                .update_packmap_consuming(&auth, upd(PACKMAP, Missing, map), &pending))
            .unwrap_err()
            .code(),
            Code::PermissionDenied
        );
        let partition = env.pipe.shards.ref_shard(&repo, PACKMAP);
        for key in [
            keys::ref_key(&repo.name, PACKMAP),
            keys::membership(&repo.name, &map),
        ] {
            assert!(now(env.pipe.meta.get(&partition, &key)).unwrap().is_none());
        }
        assert!(env.batches().is_empty());
    }
}

#[test]
fn unconditional_present_ref_can_overwrite_a_changed_target_with_the_same_admitted_effect() {
    let clock = clock();
    let kv = store(&clock);
    seed(&kv, &[(HEAD, A)]);
    let raced = Arc::new(AtomicBool::new(false));
    let once = raced.clone();
    let meta = Spy::new(kv).hook(move |kv, _, batch| {
        if batch
            .writes
            .iter()
            .any(|w| matches!(w, Write::Put(k, _) if *k == keys::ref_key(&repo_name(), HEAD)))
            && !once.swap(true, Ordering::SeqCst)
        {
            seed(kv, &[(HEAD, B)]);
        }
    });
    let env = build(
        cfg(authv2()),
        meta,
        with_admission(Effects::default()),
        clock,
    );
    let update = upd(HEAD, Any, C);
    assert_eq!(
        env.update(&Req::update(&key(7), 1, &update, T0), &update)
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert!(raced.load(Ordering::SeqCst));
    assert_eq!(env.read(HEAD), Some(C));
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].updates,
        vec![resolved(HEAD, Some(C), RefEffect::Replace)]
    );
    assert!(matches!(
        reservation(&env, &ns(), "effects-0"),
        codec::ReservationV1::Committed { .. }
    ));
}

#[test]
fn failed_inline_verification_aborts_only_the_new_ref_reservation() {
    let (env, owner, identity) = environment_with_hooks(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
        None,
        with_admission(Effects::default()),
    );
    let (bytes, actual_head) = pack();
    assert_ne!(actual_head, A);
    let node = encode_packlist(None, &[hash(&bytes)]).unwrap();
    let tickets = vec![
        begin(&env, &owner, &identity, &bytes, 1),
        begin(&env, &owner, &identity, &node, 2),
    ];
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 3))
        .unwrap();
    assert!(
        now(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, A),
            upd(PACKMAP, Missing, hash(&node)),
            tickets,
        ))
        .is_err(),
        "head outside the uploaded closure must fail verification"
    );
    let partition = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    let seen = env.pipe.hooks.admission.0.lock().unwrap();
    assert_eq!(
        seen.len(),
        3,
        "verification happens after the ref reservation is granted"
    );
    assert_eq!(seen[2].procedure, Procedure::AdvanceRefs);
    assert!(
        seen[2]
            .updates
            .iter()
            .all(|r| r.effect == RefEffect::Create)
    );
    assert!(matches!(
        reservation(&env, &partition, "effects-2"),
        codec::ReservationV1::Aborted { .. }
    ));
    for rid in ["effects-0", "effects-1"] {
        assert!(matches!(
            reservation(&env, &partition, rid),
            codec::ReservationV1::Ticketed { .. }
        ));
    }
    for name in [HEAD, PACKMAP] {
        assert!(
            now(env
                .pipe
                .meta
                .get(&partition, &keys::ref_key(&auth.repo().repo.name, name)))
            .unwrap()
            .is_none()
        );
    }
}
