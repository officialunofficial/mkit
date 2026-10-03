//! Denial proof retains its original attempt window with fresh business guards.
use super::*;
use crate::pipeline::reservation::PendingGuard;
use std::collections::BTreeSet;

const DIRECTORY_SCANS: u32 = crate::takedown::directory::DIRECTORY_SHARDS as u32;

fn proof_env(delay: i64, mutate: bool, d34: bool) -> (Env, Arc<AtomicU32>) {
    let clock = clock();
    let mut meta = Spy::new(store(&clock));
    let scans = Arc::new(AtomicU32::new(0));
    let count = scans.clone();
    let time = clock.clone();
    let delayed = AtomicBool::new(false);
    let source = if d34 {
        D34Shards.ref_shard(&repo(), HEAD)
    } else {
        ns()
    };
    meta.scan_hook = Some(Box::new(move |store, p| {
        if matches!(p, Partition::ContentShard(_)) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        if *p == Partition::ContentShard(0) {
            if !delayed.swap(true, Ordering::SeqCst) {
                time.set(time.now_ms() + delay);
            }
            if mutate {
                now(store.apply(
                    &source,
                    Batch::new().put(keys::ref_key(&repo_name(), HEAD), codec::encode_ref_id(&B)),
                ))
                .unwrap();
            }
        }
    }));
    let mut config = cfg(AuthMode::Open);
    if d34 {
        config.sharding = Sharding::D34;
    }
    let mut env = build(config, meta, Hooks::new(), clock);
    env.pipe.cfg.indexed = Some(crate::indexed::IndexedConfig::scheduled(1 << 30));
    env.pipe.cfg.takedown_denial = true;
    (env, scans)
}

fn run_proved(
    env: &Env,
    pending: Option<&PendingGuard>,
    leased: bool,
) -> Result<StoredResult, ServerError> {
    run_proved_with(env, pending, leased, |_| {})
}

fn run_proved_with(
    env: &Env,
    pending: Option<&PendingGuard>,
    leased: bool,
    edit: impl FnOnce(&mut WriteRequest<'_>),
) -> Result<StoredResult, ServerError> {
    run_proved_ticket(env, pending, leased, edit, false, None)
}

fn run_proved_ticket(
    env: &Env,
    pending: Option<&PendingGuard>,
    leased: bool,
    edit: impl FnOnce(&mut WriteRequest<'_>),
    expired_ticket: bool,
    budget: Option<&crate::pipeline::publication_budget::PublicationBudget>,
) -> Result<StoredResult, ServerError> {
    let refs = [upd(HEAD, Missing, C)];
    let ids = BTreeSet::from([A]);
    let repo = repo();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let ticket_ids = [crate::store::tickets::ticket_id("s:proof-ticket")];
    let ticket = codec::encode_ticket(&codec::TicketV1 {
        authority_generation: None,
        repo: repo.name.clone(),
        ref_name: HEAD.into(),
        signer: A,
        pack_id: B,
        bytes: 100,
        part_size: 8 << 20,
        created_at_ms: ms(T0),
        expires_at_ms: ms(T0) + 1000,
        reservation_id: "s:proof-ticket".into(),
        upload_session: None,
    });
    if expired_ticket {
        now(env.pipe.meta.inner.apply(
            &source,
            Batch::new().put(keys::ticket(&ticket_ids[0]), ticket.clone()),
        ))
        .unwrap();
    }
    let mut req = WriteRequest {
        denial_ids: Some(&ids),
        denial_packs: &[],
        authority_store: AuthorityStore::Guarded,
        authority_generation: None,
        repo: &repo.name,
        kind: if expired_ticket {
            WriteKind::AdvanceRefs
        } else {
            WriteKind::UpdateRef
        },
        refs: &refs,
        ref_index: None,
        replay: None,
        charges: &[],
        namespace_charge: None,
        grant: None,
        lease: leased.then_some(lease::LeaseWrite {
            value: codec::EpochLease {
                authority_ready: None,
                authority_generation: None,
                epoch: 0,
                expires_at_ms: ms(T0) + 30_000,
                config_version: 1,
            },
            install: true,
        }),
        layout_version: false,
        mark_repo_known: false,
        begin: None,
        advance: expired_ticket.then_some(advance::AdvanceWrite {
            ids: &ticket_ids,
            signer: A,
            head_ref: HEAD,
            repo_id: &repo,
            repository: REPO,
            source: &source,
            shards: env.pipe.shards.as_ref(),
        }),
        implicit: None,
        rejection: None,
        publication: None,
        pending,
    };
    edit(&mut req);
    let mut ahead = snapshot(&req, &[]);
    if expired_ticket {
        ahead.insert(keys::ticket(&ticket_ids[0]), Some(ticket));
    }
    let a = env.auth(&Req::unsigned(Procedure::UpdateRef)).unwrap();
    let op = env
        .pipe
        .identify(&a, OpKind::UpdateRef(refs[0].clone()))
        .unwrap();
    now(env
        .pipe
        .apply_loop(&op, &a, &source, &req, Some(ahead), budget))
}

#[test]
fn cold_proof_expires_original_window_then_warm_reproof_uses_new_attempt() {
    for delay in [11_000, 31_000] {
        let (env, scans) = proof_env(delay, false, false);
        run_proved(&env, None, false).unwrap();
        assert_eq!(scans.load(Ordering::SeqCst), 2 * DIRECTORY_SCANS);
        let batches = env.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0].preconditions[0],
            Precondition::NotAfter(ms(T0) + 10_000)
        );
        assert_eq!(
            batches[1].preconditions[0],
            Precondition::NotAfter(ms(T0 + delay) + 10_000)
        );
    }
}

#[test]
fn proof_refreshes_ahead_rows_before_guarded_plan() {
    let (env, scans) = proof_env(11_000, true, false);
    assert_eq!(
        run_proved(&env, None, false).unwrap(),
        StoredResult::UpdateRef(UpdateRefResult::Conflict { current: Some(B) })
    );
    assert_eq!(scans.load(Ordering::SeqCst), DIRECTORY_SCANS);
    assert!(env.batches().is_empty());
}

#[test]
fn proof_crossing_initial_lease_renews_before_plan() {
    let (env, scans) = proof_env(31_000, false, true);
    run_proved(&env, None, true).unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 2 * DIRECTORY_SCANS);
    let source = D34Shards.ref_shard(&repo(), HEAD);
    let value = now(env.pipe.meta.inner.get(&source, &keys::epoch_lease()))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_epoch_lease(&value).unwrap().expires_at_ms,
        ms(T0 + 31_000) + 30_000
    );
    assert_eq!(
        env.batches().last().unwrap().preconditions[0],
        Precondition::NotAfter(ms(T0 + 31_000) + 10_000)
    );
}

#[test]
fn proof_does_not_extend_fixed_pending_deadline() {
    let (env, scans) = proof_env(11_000, false, false);
    let pending = PendingGuard {
        rid: "s:proof".into(),
        repository: REPO.into(),
        procedure: None,
        key: keys::reservation("s:proof").unwrap(),
        value: codec::encode_reservation(&codec::ReservationV1::Pending {
            repository: REPO.into(),
            created_at_ms: ms(T0),
            reconcile_at_ms: ms(T0) + 13_000,
            op: codec::PendingOp::Write,
            procedure: None,
        }),
        apply_deadline_ms: ms(T0) + 10_000,
    };
    now(env.pipe.meta.inner.apply(
        &ns(),
        Batch::new().put(pending.key.clone(), pending.value.clone()),
    ))
    .unwrap();
    assert_eq!(
        run_proved(&env, Some(&pending), false).unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(scans.load(Ordering::SeqCst), 2 * DIRECTORY_SCANS);
    assert!(
        env.batches().iter().all(
            |batch| batch.preconditions[0] == Precondition::NotAfter(pending.apply_deadline_ms)
        )
    );
    assert!(
        now(env
            .pipe
            .meta
            .inner
            .get(&ns(), &keys::ref_key(&repo_name(), HEAD)))
        .unwrap()
        .is_none()
    );
}

#[test]
fn cas_retries_repeat_proof_without_resetting_nine_thousand_allowance() {
    let (mut env, scans) = proof_env(0, false, true);
    // Stale monotonic registrations force two expensive complete proofs.
    // The third exhausts the original ledger instead of receiving a new one.
    for i in 0..4200u32 {
        let mut object = [0; 32];
        object[28..].copy_from_slice(&i.to_be_bytes());
        now(crate::takedown::directory::reserve(
            env.pipe.meta.inner.as_ref(),
            &object,
            ms(T0),
        ))
        .unwrap();
    }
    let races = Arc::new(AtomicU32::new(0));
    let count = races.clone();
    env.pipe.meta.hook = Some(Box::new(move |store, p, _| {
        if !matches!(p, Partition::Ref { .. }) {
            return;
        }
        let n = count.fetch_add(1, Ordering::SeqCst);
        now(store.apply(
            p,
            Batch::new().put(
                keys::epoch_lease(),
                codec::encode_epoch_lease(&codec::EpochLease {
                    authority_ready: None,
                    authority_generation: None,
                    epoch: 0,
                    expires_at_ms: ms(T0) + 30_001 + u64::from(n),
                    config_version: 1,
                }),
            ),
        ))
        .unwrap();
    }));
    assert_eq!(
        run_proved(&env, None, true).unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(races.load(Ordering::SeqCst), 2);
    assert!(scans.load(Ordering::SeqCst) <= 9000);
    assert!(scans.load(Ordering::SeqCst) > 3 * DIRECTORY_SCANS);
    assert!(env.pipe.meta.calls() <= 9000 + 32);
}

#[test]
fn proof_reobserves_revoked_epoch_and_authority_before_planning() {
    for authority in [false, true] {
        let (mut env, scans) = proof_env(11_000, false, false);
        let previous = env.pipe.meta.scan_hook.take().unwrap();
        env.pipe.meta.scan_hook = Some(Box::new(move |store, p| {
            previous(store, p);
            if *p == Partition::ContentShard(0) {
                let key = if authority {
                    keys::authority_generation()
                } else {
                    keys::grant_epoch()
                };
                now(store.apply(&ns(), Batch::new().put(key, codec::encode_u64(1)))).unwrap();
            }
        }));
        let error = run_proved_with(&env, None, false, |req| {
            if authority {
                req.authority_generation = Some(0);
            } else {
                req.grant = Some(crate::op::GrantRef {
                    id: [9; 32],
                    epoch: 0,
                    presence_requirement: None,
                });
            }
        })
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(scans.load(Ordering::SeqCst), DIRECTORY_SCANS);
        assert!(env.batches().is_empty());
    }
}

#[test]
fn proof_keeps_signed_expiry_deadline_cap() {
    let (env, scans) = proof_env(40_000, false, false);
    let expiry = T0 + 1000;
    let error = run_proved_with(&env, None, false, |req| {
        req.replay = Some(ReplayGuard {
            scope: [1; 32],
            fingerprint: [2; 32],
            expires_at_ms: expiry,
        });
    })
    .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(scans.load(Ordering::SeqCst), DIRECTORY_SCANS);
    assert_eq!(
        env.batches()[0].preconditions[0],
        Precondition::NotAfter(ms(T0) + 10_000)
    );
    assert!(
        now(env
            .pipe
            .meta
            .inner
            .get(&ns(), &keys::ref_key(&repo_name(), HEAD)))
        .unwrap()
        .is_none()
    );
}

#[test]
fn failed_cas_reproves_and_renews_the_retry_lease() {
    let (mut env, scans) = proof_env(0, false, true);
    let time = env.clock.clone();
    let fired = AtomicBool::new(false);
    env.pipe.meta.hook = Some(Box::new(move |store, p, batch| {
        if matches!(p, Partition::Ref { .. }) && !fired.swap(true, Ordering::SeqCst) {
            let value = batch
                .writes
                .iter()
                .find_map(|write| match write {
                    Write::Put(key, value) if *key == keys::epoch_lease() => Some(value),
                    _ => None,
                })
                .unwrap();
            now(store.apply(p, Batch::new().put(keys::epoch_lease(), value.clone()))).unwrap();
        }
    }));
    env.pipe.meta.after_hook = Some(Box::new(move |_, p, _, outcome| {
        if matches!(p, Partition::Ref { .. })
            && matches!(outcome, BatchOutcome::PreconditionFailed { .. })
        {
            // Age the lease between attempts, after a genuinely failed CAS.
            time.set(T0 + 31_000);
        }
    }));
    run_proved(&env, None, true).unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 2 * DIRECTORY_SCANS);
    let source = D34Shards.ref_shard(&repo(), HEAD);
    let value = now(env.pipe.meta.inner.get(&source, &keys::epoch_lease()))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_epoch_lease(&value).unwrap().expires_at_ms,
        ms(T0 + 31_000) + 30_000
    );
    assert_eq!(
        env.batches().last().unwrap().preconditions[0],
        Precondition::NotAfter(ms(T0 + 31_000) + 10_000)
    );
}

#[test]
fn repeated_slow_proof_cannot_refresh_either_attempt_window() {
    let (mut env, scans) = proof_env(0, false, true);
    let previous = env.pipe.meta.scan_hook.take().unwrap();
    let time = env.clock.clone();
    env.pipe.meta.scan_hook = Some(Box::new(move |store, p| {
        previous(store, p);
        if *p == Partition::ContentShard(0) {
            time.set(time.now_ms() + 31_000);
        }
    }));
    assert_eq!(
        run_proved(&env, None, true).unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(scans.load(Ordering::SeqCst), 2 * DIRECTORY_SCANS);
    let all = env.batches();
    let ref_key = keys::ref_key(&repo_name(), HEAD);
    let batches: Vec<_> = all
        .iter()
        .filter(|batch| {
            batch
                .writes
                .iter()
                .any(|write| matches!(write, Write::Put(key, _) if *key == ref_key))
        })
        .collect();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[0].preconditions[0],
        Precondition::NotAfter(ms(T0) + 10_000)
    );
    assert_eq!(
        batches[1].preconditions[0],
        Precondition::NotAfter(ms(T0 + 31_000) + 10_000)
    );
    assert!(
        now(env.pipe.meta.inner.get(
            &D34Shards.ref_shard(&repo(), HEAD),
            &keys::ref_key(&repo_name(), HEAD)
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn proof_rechecks_ticket_expiry_on_fresh_business_clock() {
    let (env, scans) = proof_env(11_000, false, false);
    let error = run_proved_ticket(&env, None, false, |_| {}, true, None).unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), "invalid or expired upload ticket");
    assert_eq!(scans.load(Ordering::SeqCst), DIRECTORY_SCANS);
    assert!(env.batches().is_empty());
}

#[test]
fn proof_cannot_guard_new_epoch_while_committing_initial_lease() {
    for install in [false, true] {
        let (mut env, scans) = proof_env(0, false, true);
        let previous = env.pipe.meta.scan_hook.take().unwrap();
        let source = D34Shards.ref_shard(&repo(), HEAD);
        let pushed = codec::EpochLease {
            authority_ready: None,
            authority_generation: None,
            epoch: 1,
            expires_at_ms: ms(T0) + 30_000,
            config_version: 1,
        };
        let target = source.clone();
        env.pipe.meta.scan_hook = Some(Box::new(move |store, p| {
            previous(store, p);
            if *p == Partition::ContentShard(0) {
                now(store.apply(
                    &target,
                    Batch::new().put(keys::epoch_lease(), codec::encode_epoch_lease(&pushed)),
                ))
                .unwrap();
            }
        }));
        let error = run_proved_with(&env, None, true, |req| {
            req.grant = Some(crate::op::GrantRef {
                id: [9; 32],
                epoch: 0,
                presence_requirement: None,
            });
            req.lease.as_mut().unwrap().install = install;
        })
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(scans.load(Ordering::SeqCst), DIRECTORY_SCANS);
        assert!(env.batches().is_empty());
        assert_eq!(
            now(env.pipe.meta.inner.get(&source, &keys::epoch_lease())).unwrap(),
            Some(codec::encode_epoch_lease(&pushed))
        );
    }
}

#[test]
fn action_after_final_clear_cannot_borrow_a_new_commit_window() {
    let (mut env, scans) = proof_env(0, false, false);
    let fired = Arc::new(AtomicBool::new(false));
    let installed = fired.clone();
    let time = env.clock.clone();
    env.pipe.meta.read_many_hook = Some(Box::new(move |store, p, _| {
        // apply_loop's fresh source snapshot is after ALL descriptor pages and
        // final direct target checks. No earlier proof read uses this source.
        if *p == ns() && !installed.swap(true, Ordering::SeqCst) {
            time.set(T0 + 11_000);
            now(
                crate::store::ContentIndex::new(crate::store::BorrowedStore(store)).block(
                    &A,
                    &crate::store::BlockEntry::new("after proof", ms(T0 + 10_001)),
                    ms(T0 + 10_001),
                ),
            )
            .unwrap();
        }
    }));
    let result = run_proved(&env, None, false);
    assert!(fired.load(Ordering::SeqCst));
    assert!(scans.load(Ordering::SeqCst) >= DIRECTORY_SCANS);
    assert!(
        now(crate::takedown::denial::denied(
            env.pipe.meta.inner.as_ref(),
            &A
        ))
        .unwrap()
    );
    eprintln!(
        "after-final-clear evidence: result={result:?} scans={} now={} deadlines={:?} ref={:?}",
        scans.load(Ordering::SeqCst),
        env.clock.now_ms(),
        env.batches()
            .iter()
            .map(|batch| &batch.preconditions[0])
            .collect::<Vec<_>>(),
        now(env
            .pipe
            .meta
            .inner
            .get(&ns(), &keys::ref_key(&repo_name(), HEAD)))
        .unwrap()
    );
    assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    assert!(
        now(env
            .pipe
            .meta
            .inner
            .get(&ns(), &keys::ref_key(&repo_name(), HEAD)))
        .unwrap()
        .is_none()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Keep the canonical signed writer, relay, operator and barrier setup together."
)]
fn signed_takedown_after_proof_cannot_publish_a_reused_canonical_pair() {
    use crate::admin::{BodyCapture, Config, Engine, TAKEDOWN_PATH};
    use base64::Engine as _;
    use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use mkit_core::sign::{KeyPair, sign_commit};
    use serde_json::json;

    let (mut env, owner, identity) = super::indexed::environment_with(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
    );
    let file = Object::Blob(Blob {
        data: b"post-proof file".to_vec(),
    });
    let file_id = file.id().unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: file_id,
        }],
    });
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        vec![],
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"post-proof pair".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = mkit_core::pack::PackWriter::new_raw_only();
    for object in [&file, &tree, &commit] {
        writer
            .push_raw(
                object.id().unwrap(),
                &mkit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
    }
    let bytes = writer.finish().unwrap();
    let map_bytes = mkit_core::transfer::encode_packlist(None, &[hash(&bytes)]).unwrap();
    let map = hash(&map_bytes);
    let tickets = vec![
        super::indexed::begin_and_upload(&env, &owner, &identity, &bytes, 9900),
        super::indexed::begin_and_upload(&env, &owner, &identity, &map_bytes, 9901),
    ];
    let first = env
        .auth(&super::indexed::signed(
            &owner,
            &identity,
            Procedure::AdvanceRefs,
            9902,
        ))
        .unwrap();
    assert_eq!(
        now(env.pipe.advance_refs_with_tickets(
            &first,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, map),
            tickets,
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    let repo = first.repo().repo.clone();
    let relay = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
        target: crate::store::BorrowedStore(&env.pipe.meta),
        hook: crate::relay::NoHook,
        budget: crate::relay::RelayBudget::default(),
    });
    for _ in 0..8 {
        now(crate::timers::run_due(
            &env.pipe.meta,
            &env.pipe.shards.ref_shard(&repo, HEAD),
            &relay,
            env.clock.as_ref(),
            ms(T0),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
    }
    drop(relay);
    assert!(
        now(crate::store::index::holds_any(
            &env.pipe.meta,
            env.pipe.shards.as_ref(),
            &repo,
            &[file_id]
        ))
        .unwrap()
        .unwrap()
    );
    let root = env.pipe.shards.coordinator(&repo.namespace);
    let operator = SigningKey::from_bytes(&[71; 32]);
    let config = Config::parse(AUDIENCE, &json!({"version":1,"keys":[{
        "keyId":"operator", "alg":"ed25519", "publicKey":to_hex(operator.verifying_key().as_bytes()),
        "roles":["moderation"]
    }]}).to_string()).unwrap();
    let engine = Arc::new(
        Engine::new(env.pipe.meta.inner.clone(), root.clone(), config).with_operations(Arc::new(
            crate::takedown::Service::new(
                env.pipe.meta.inner.clone(),
                root,
                env.pipe.shards.clone(),
            ),
        )),
    );
    let input = json!({"repository":identity,"operationId":"post-proof-pair",
        "objectIds":[base64::engine::general_purpose::STANDARD.encode(file_id)],
        "reason":"policy review","reasonToken":"policy"});
    let mut body = BodyCapture::default();
    body.push(input.to_string().as_bytes());
    let nonce = to_hex(&[91; 32]);
    let digest = body.digest();
    let canonical = format!(
        "mkit-admin:v1\noperator\n{AUDIENCE}\n{TAKEDOWN_PATH}\n{digest}\n{T0}\n{}\n{nonce}",
        T0 + 60_000
    );
    let signature = to_hex_bytes(&operator.sign(&hash(canonical.as_bytes())).to_bytes());
    let headers = crate::admin::HEADER_NAMES
        .into_iter()
        .zip([
            "1".into(),
            "operator".into(),
            AUDIENCE.into(),
            T0.to_string(),
            (T0 + 60_000).to_string(),
            nonce,
            digest,
            signature,
        ])
        .map(|(name, value)| (name.into(), value))
        .collect();
    let scans = Arc::new(AtomicU32::new(0));
    let count = scans.clone();
    env.pipe.meta.scan_hook = Some(Box::new(move |_, p| {
        if matches!(p, Partition::ContentShard(_)) {
            count.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let fired = Arc::new(AtomicBool::new(false));
    let activated = fired.clone();
    let count = scans.clone();
    let source = env.pipe.shards.ref_shard(&repo, "refs/heads/reuse");
    let barrier_source = source.clone();
    let time = env.clock.clone();
    env.pipe.meta.read_many_hook = Some(Box::new(move |_, p, _| {
        if *p == barrier_source
            && count.load(Ordering::SeqCst) >= DIRECTORY_SCANS
            && !activated.swap(true, Ordering::SeqCst)
        {
            time.set(T0 + 10_001);
            let response = now(engine.handle(TAKEDOWN_PATH, &headers, &body, T0 + 10_001));
            assert_eq!(
                response.status,
                200,
                "{}",
                String::from_utf8_lossy(&response.body)
            );
            time.set(T0 + 11_000);
        }
    }));
    env.pipe.cfg.takedown_denial = true;
    let request = env
        .auth(&super::indexed::signed(
            &owner,
            &identity,
            Procedure::AdvanceRefs,
            9903,
        ))
        .unwrap();
    let result = now(env.pipe.advance_refs(
        &request,
        upd("refs/heads/reuse", Missing, head),
        upd("refs/mkit/packmap/reuse", Missing, map),
    ));
    assert!(fired.load(Ordering::SeqCst));
    assert!(
        now(crate::takedown::denial::denied(
            env.pipe.meta.inner.as_ref(),
            &file_id
        ))
        .unwrap()
    );
    assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    for name in ["refs/heads/reuse", "refs/mkit/packmap/reuse"] {
        for key in [
            keys::ref_key(&repo.name, name),
            keys::published_ref(&repo.name, name),
        ] {
            assert!(
                now(env.pipe.meta.inner.get(&source, &key))
                    .unwrap()
                    .is_none()
            );
        }
    }
    assert_eq!(
        now(env
            .pipe
            .meta
            .inner
            .get(&source, &keys::ref_key(&repo.name, HEAD)))
        .unwrap(),
        Some(codec::encode_ref_id(&head))
    );
}

#[test]
fn replans_share_one_proof_ledger_and_exhaustion_is_capacity() {
    use crate::pipeline::publication_budget::{PublicationBudget, SETTLEMENT_RESERVE};
    // The cold proof outlives its commit window, so the loop proves twice.
    let spent = {
        let (env, _) = proof_env(11_000, false, false);
        let ledger = PublicationBudget::new();
        run_proved_ticket(&env, None, false, |_| {}, false, Some(&ledger)).unwrap();
        ledger.proof().used()
    };
    assert!(spent > 2 * DIRECTORY_SCANS, "both proofs charge one ledger");
    // Exactly the aggregate allowance succeeds; one call fewer is capacity on the
    // second proof, never a verdict about the content and never a commit.
    let (env, _) = proof_env(11_000, false, false);
    let ledger = PublicationBudget::with_request_calls(spent + SETTLEMENT_RESERVE);
    run_proved_ticket(&env, None, false, |_| {}, false, Some(&ledger)).unwrap();
    assert_eq!(ledger.proof().used(), spent);
    let (env, _) = proof_env(11_000, false, false);
    let ledger = PublicationBudget::with_request_calls(spent - 1 + SETTLEMENT_RESERVE);
    let error = run_proved_ticket(&env, None, false, |_| {}, false, Some(&ledger)).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(
        error.public_message(),
        "publication verification capacity exhausted"
    );
    assert!(ledger.proof().refused());
    assert!(
        now(env.pipe.meta.inner.get(
            &env.pipe.shards.ref_shard(&repo(), HEAD),
            &keys::ref_key(&repo_name(), HEAD)
        ))
        .unwrap()
        .is_none()
    );
}
