//! Slow global proof precedes every fresh bounded write plan.
use super::*;
use crate::pipeline::reservation::PendingGuard;
use std::collections::BTreeSet;

fn proof_env(delay: i64, mutate: bool, d34: bool) -> (Env, Arc<AtomicU32>) {
    let clock = clock();
    let mut meta = Spy::new(store(&clock));
    let scans = Arc::new(AtomicU32::new(0));
    let count = scans.clone();
    let time = clock.clone();
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
            time.set(time.now_ms() + delay);
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
    run_proved_ticket(env, pending, leased, edit, false)
}

fn run_proved_ticket(
    env: &Env,
    pending: Option<&PendingGuard>,
    leased: bool,
    edit: impl FnOnce(&mut WriteRequest<'_>),
    expired_ticket: bool,
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
    now(env.pipe.apply_loop(&op, &a, &source, &req, Some(ahead)))
}

#[test]
fn proof_crossing_initial_window_uses_fresh_ten_second_deadline() {
    for delay in [11_000, 31_000] {
        let (env, scans) = proof_env(delay, false, false);
        run_proved(&env, None, false).unwrap();
        assert_eq!(scans.load(Ordering::SeqCst), 4096);
        let batches = env.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(
            batches[0].preconditions[0],
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
    assert_eq!(scans.load(Ordering::SeqCst), 4096);
    assert!(env.batches().is_empty());
}

#[test]
fn proof_crossing_initial_lease_renews_before_plan() {
    let (env, scans) = proof_env(31_000, false, true);
    run_proved(&env, None, true).unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 4096);
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
        key: keys::reservation("s:proof").unwrap(),
        value: codec::encode_reservation(&codec::ReservationV1::Pending {
            repository: REPO.into(),
            created_at_ms: ms(T0),
            reconcile_at_ms: ms(T0) + 13_000,
            op: codec::PendingOp::Write,
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
    assert_eq!(scans.load(Ordering::SeqCst), 8192);
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
    assert!(scans.load(Ordering::SeqCst) > 8192);
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
        assert_eq!(scans.load(Ordering::SeqCst), 4096);
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
    assert_eq!(scans.load(Ordering::SeqCst), 4096);
    assert_eq!(
        env.batches()[0].preconditions[0],
        Precondition::NotAfter(ms(expiry + MAX_CLOCK_LEAD_MS))
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
    let (mut env, scans) = proof_env(31_000, false, true);
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
    run_proved(&env, None, true).unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 8192);
    let source = D34Shards.ref_shard(&repo(), HEAD);
    let value = now(env.pipe.meta.inner.get(&source, &keys::epoch_lease()))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_epoch_lease(&value).unwrap().expires_at_ms,
        ms(T0 + 62_000) + 30_000
    );
    assert_eq!(
        env.batches().last().unwrap().preconditions[0],
        Precondition::NotAfter(ms(T0 + 62_000) + 10_000)
    );
}

#[test]
fn proof_rechecks_ticket_expiry_on_fresh_business_clock() {
    let (env, scans) = proof_env(11_000, false, false);
    let error = run_proved_ticket(&env, None, false, |_| {}, true).unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), "invalid or expired upload ticket");
    assert_eq!(scans.load(Ordering::SeqCst), 4096);
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
        assert_eq!(scans.load(Ordering::SeqCst), 4096);
        assert!(env.batches().is_empty());
        assert_eq!(
            now(env.pipe.meta.inner.get(&source, &keys::epoch_lease())).unwrap(),
            Some(codec::encode_epoch_lease(&pushed))
        );
    }
}
