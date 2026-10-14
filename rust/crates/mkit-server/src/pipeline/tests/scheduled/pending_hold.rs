//! Request-local holds over the real scheduled upload and advance paths.
use super::*;
use crate::rt::{BoxFuture, ManualSleep, Sleep};
use core::future::Future;
use core::task::{Context, Poll};

/// Poll sleeps advance logical time; the outer timeout remains pending.
struct ClockSleep(Arc<ManualClock>);
impl Sleep for ClockSleep {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let clock = self.0.clone();
        Box::pin(async move {
            if duration <= Duration::from_millis(100) {
                clock.advance(i64::try_from(duration.as_millis()).unwrap());
            } else {
                futures::future::pending::<()>().await;
            }
        })
    }
}

fn assert_same_pending(actual: &ServerError, expected: &ServerError) {
    assert_eq!(actual.code(), expected.code());
    assert_eq!(actual.http_status(), expected.http_status());
    assert_eq!(actual.public_message(), expected.public_message());
    assert_eq!(actual.headers(), expected.headers());
    assert_eq!(actual.details(), expected.details());
}

fn settle<H: HookSet>(env: &Env<H>, source: &Partition) {
    let handler = VerifyTimer {
        remote: Ref(&env.pipe.meta),
        blobs: Ref(&env.pipe.blobs),
        windows: BlobWindows(&env.pipe.blobs),
        shards: env.pipe.shards.clone(),
        cfg: env.pipe.cfg.indexed.unwrap(),
        limits: SliceLimits::default(),
        lease: LeaseParams::from(&env.pipe.cfg),
        clock: env.clock.clone(),
        metrics: env.metrics.clone(),
        extension: FailClosedExtraction,
    };
    let registry = TimerRegistry::new()
        .register(handler)
        .register(RelayHandler {
            target: Ref(&env.pipe.meta),
            hook: NoHook,
            budget: RelayBudget::default(),
        });
    // Progress through the real timer boundaries without a client poll delay.
    for _ in 0..12 {
        block_on(run_due(
            &env.pipe.meta,
            source,
            &registry,
            env.clock.as_ref(),
            ms(env.clock.now_ms()),
            &TickBudget::default(),
        ))
        .unwrap();
        env.clock.advance(1);
    }
}

#[test]
fn zero_hold_keeps_pending_bytes_and_backend_calls_unchanged() {
    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 950);
    advance(&env, &owner, &identity, 951, head, pack_id, vec![ticket]).unwrap_err();
    env.pipe.meta.calls.store(0, Ordering::SeqCst);
    let expected = advance(&env, &owner, &identity, 951, head, pack_id, vec![ticket]).unwrap_err();
    let calls = env.pipe.meta.calls.load(Ordering::SeqCst);
    let sleeper = Arc::new(ManualSleep::new());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::ZERO,
        sleeper.clone(),
        ms(env.clock.now_ms()) + 15_000,
    );
    env.pipe.meta.calls.store(0, Ordering::SeqCst);
    let actual = advance(&env, &owner, &identity, 951, head, pack_id, vec![ticket]).unwrap_err();
    assert_same_pending(&actual, &expected);
    assert!(sleeper.requested().is_empty());
    assert_eq!(env.pipe.meta.calls.load(Ordering::SeqCst), calls);
}

#[test]
fn cap_preserves_pending_bytes_and_adds_at_most_twenty_reads() {
    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 960);
    let expected = advance(&env, &owner, &identity, 961, head, pack_id, vec![ticket]).unwrap_err();
    env.pipe.meta.calls.store(0, Ordering::SeqCst);
    advance(&env, &owner, &identity, 961, head, pack_id, vec![ticket]).unwrap_err();
    let ordinary_calls = env.pipe.meta.calls.load(Ordering::SeqCst);
    let before = ms(env.clock.now_ms());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::from_secs(30),
        Arc::new(ClockSleep(env.clock.clone())),
        before + 15_000,
    );
    env.pipe.meta.calls.store(0, Ordering::SeqCst);
    let actual = advance(&env, &owner, &identity, 961, head, pack_id, vec![ticket]).unwrap_err();
    assert_same_pending(&actual, &expected);
    assert_eq!(ms(env.clock.now_ms()) - before, 2_000);
    assert_eq!(
        env.pipe.meta.calls.load(Ordering::SeqCst),
        ordinary_calls + 20
    );
}

#[test]
fn expiry_and_elapsed_request_budget_leave_no_hold() {
    for near_expiry in [false, true] {
        let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
        let (bytes, head) = pack();
        let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 970);
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 971);
        let auth = env.auth(&request).unwrap();
        if near_expiry {
            env.clock.set(T0 + 300_000 - 250);
        }
        let sleeper = Arc::new(ManualSleep::new());
        let before = ms(env.clock.now_ms());
        let deadline = if near_expiry {
            before + 15_000
        } else {
            before + 250
        };
        env.pipe =
            env.pipe
                .with_pending_advance_hold(Duration::from_secs(2), sleeper.clone(), deadline);
        let error = block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, hash(&bytes)),
            vec![ticket],
        ))
        .unwrap_err();
        assert_eq!(error.public_message(), "pack verification pending");
        assert!(sleeper.requested().is_empty());
        assert_eq!(ms(env.clock.now_ms()), before);
    }
}

#[test]
fn request_budget_caps_wait_before_safety_margin() {
    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (bytes, head) = pack();
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 980);
    let before = ms(env.clock.now_ms());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::from_secs(2),
        Arc::new(ClockSleep(env.clock.clone())),
        before + 550,
    );
    assert_eq!(
        advance(
            &env,
            &owner,
            &identity,
            981,
            head,
            hash(&bytes),
            vec![ticket]
        )
        .unwrap_err()
        .public_message(),
        "pack verification pending"
    );
    assert_eq!(ms(env.clock.now_ms()) - before, 300);
}

#[test]
fn small_pack_completes_during_hold_and_lost_reply_replays() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let baseline_ms = small_pack_with_client_poll(sharding);
        let (mut env, owner, identity) = environment_with(sharding, scheduled());
        let (bytes, head) = pack();
        let pack_id = hash(&bytes);
        let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 990);
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 991);
        let auth = env.auth(&request).unwrap();
        let repo = auth.repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        let before = ms(env.clock.now_ms());
        let sleeper = Arc::new(ManualSleep::new());
        env.pipe = env.pipe.with_pending_advance_hold(
            Duration::from_secs(2),
            sleeper.clone(),
            before + 15_000,
        );
        let mut waiting = Box::pin(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![ticket],
        ));
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert_advance_unmoved(&env, &repo, &[pack_id]);
        settle(&env, &source);
        // Verification finishes after twelve logical milliseconds, and the
        // held request observes it at its first 100 ms server poll.
        env.clock.advance(88);
        sleeper.fire();
        assert_eq!(block_on(waiting).unwrap(), AdvanceOutcome::Committed);
        let hold_ms = ms(env.clock.now_ms()) - before;
        assert_eq!(hold_ms, 100);
        assert!(baseline_ms - hold_ms >= 900);
        println!("{sharding:?} small-pack model: client poll={baseline_ms}ms, held={hold_ms}ms");
        assert_eq!(
            advance(&env, &owner, &identity, 991, head, pack_id, vec![ticket]).unwrap(),
            AdvanceOutcome::Committed,
            "lost reply replays the committed result"
        );
    }
}

fn small_pack_with_client_poll(sharding: Sharding) -> u64 {
    let (env, owner, identity) = environment_with(sharding, scheduled());
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 992);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 993);
    let auth = env.auth(&request).unwrap();
    let source = env.pipe.shards.ref_shard(&auth.repo().repo, HEAD);
    let start = ms(env.clock.now_ms());
    assert_eq!(
        advance(&env, &owner, &identity, 993, head, pack_id, vec![ticket])
            .unwrap_err()
            .public_message(),
        "pack verification pending"
    );
    settle(&env, &source);
    // Model the client's one-second poll delay after verification completes.
    env.clock.advance(1_000);
    assert_eq!(
        advance(&env, &owner, &identity, 993, head, pack_id, vec![ticket]).unwrap(),
        AdvanceOutcome::Committed
    );
    let elapsed = ms(env.clock.now_ms()) - start;
    assert_eq!(elapsed, 1_012);
    elapsed
}

struct MutablePreReceive(Arc<AtomicBool>);

impl PreReceive for MutablePreReceive {
    async fn check(&self, op: &Operation, _: Option<&BlobKey>) -> Result<(), ServerError> {
        if op.procedure() == Procedure::AdvanceRefs && self.0.load(Ordering::SeqCst) {
            return Err(ServerError::permission_denied("pre-receive denied"));
        }
        Ok(())
    }
}

#[test]
fn pre_receive_denial_after_hold_prevents_commit() {
    let denied = Arc::new(AtomicBool::new(false));
    let hooks = Hooks {
        authorizer: OpenAuthorizer,
        admission: DefaultAdmission,
        pre_receive: MutablePreReceive(denied.clone()),
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let (mut env, owner, identity) =
        super::super::indexed::environment_with_hooks(Sharding::Single, scheduled(), None, hooks);
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let upload_request = signed(&owner, &identity, Procedure::BeginUpload, 1_010);
    let BeginUploadResult::Ticket { id: ticket, .. } = block_on(env.pipe.begin_upload(
        &env.auth(&upload_request).unwrap(),
        HEAD,
        &pack_id,
        bytes.len() as u64,
    ))
    .unwrap() else {
        panic!("expected upload ticket");
    };
    super::super::indexed::upload(&env, &bytes, ticket);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 1_011);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let sleeper = Arc::new(ManualSleep::new());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::from_secs(2),
        sleeper.clone(),
        ms(env.clock.now_ms()) + 15_000,
    );
    let mut waiting = Box::pin(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, pack_id),
        vec![ticket],
    ));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    settle(&env, &source);
    denied.store(true, Ordering::SeqCst);
    env.clock.advance(88);
    sleeper.fire();
    let error = block_on(waiting).unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(error.public_message(), "pre-receive denied");
    for name in [HEAD, PACKMAP] {
        assert!(
            block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, name)))
                .unwrap()
                .is_none()
        );
    }
}

struct ExpiringAuthorizer {
    observed: Arc<Mutex<Vec<i64>>>,
    expires_at_ms: i64,
}

impl Authorizer for ExpiringAuthorizer {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if op.procedure() == Procedure::AdvanceRefs {
            let now = op.business_now_ms.unwrap();
            self.observed.lock().unwrap().push(now);
            if now >= self.expires_at_ms {
                return Err(ServerError::permission_denied("authorization expired"));
            }
        }
        Ok(AuthzFacts::default())
    }
}

#[test]
fn authorization_during_hold_uses_fresh_business_time() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        authorizer: ExpiringAuthorizer {
            observed: observed.clone(),
            expires_at_ms: T0 + 100,
        },
        admission: DefaultAdmission,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let (mut env, owner, identity) =
        super::super::indexed::environment_with_hooks(Sharding::Single, scheduled(), None, hooks);
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let upload_request = signed(&owner, &identity, Procedure::BeginUpload, 1_020);
    let BeginUploadResult::Ticket { id: ticket, .. } = block_on(env.pipe.begin_upload(
        &env.auth(&upload_request).unwrap(),
        HEAD,
        &pack_id,
        bytes.len() as u64,
    ))
    .unwrap() else {
        panic!("expected upload ticket");
    };
    super::super::indexed::upload(&env, &bytes, ticket);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 1_021);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let sleeper = Arc::new(ManualSleep::new());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::from_secs(2),
        sleeper.clone(),
        ms(env.clock.now_ms()) + 15_000,
    );
    let mut waiting = Box::pin(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, pack_id),
        vec![ticket],
    ));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    assert_eq!(*observed.lock().unwrap(), vec![T0]);
    settle(&env, &source);
    env.clock.advance(88);
    sleeper.fire();
    let error = block_on(waiting).unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(error.public_message(), "authorization expired");
    assert_eq!(*observed.lock().unwrap(), vec![T0, T0 + 100]);
    for name in [HEAD, PACKMAP] {
        assert!(
            block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, name)))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn cancellation_during_hold_preserves_nonce_and_competing_ref_cas() {
    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    env.pipe = env.pipe.with_write_gate();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 1_000);
    let competing_bytes = super::super::indexed::pack_with_blob(7);
    let competing_pack = hash(&competing_bytes);
    let competing_ticket = begin_and_upload(&env, &owner, &identity, &competing_bytes, 1_003);
    advance(
        &env,
        &owner,
        &identity,
        1_002,
        head,
        competing_pack,
        vec![competing_ticket],
    )
    .unwrap_err();
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 1_001);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let sleeper = Arc::new(ManualSleep::new());
    env.pipe = env.pipe.with_pending_advance_hold(
        Duration::from_secs(2),
        sleeper.clone(),
        ms(env.clock.now_ms()) + 15_000,
    );
    let mut cancelled = Box::pin(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, pack_id),
        vec![ticket],
    ));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    drop(cancelled);
    assert_advance_unmoved(&env, &repo, &[pack_id]);
    let mut waiting = Box::pin(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, pack_id),
        vec![ticket],
    ));
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    settle(&env, &source);
    // A second request can advance while the first request is asleep.
    assert_eq!(
        advance(
            &env,
            &owner,
            &identity,
            1_002,
            head,
            competing_pack,
            vec![competing_ticket]
        )
        .unwrap(),
        AdvanceOutcome::Committed
    );
    sleeper.fire();
    let Poll::Ready(result) = waiting.as_mut().poll(&mut cx) else {
        panic!("the completed job must wake the advance");
    };
    assert_eq!(result.unwrap(), AdvanceOutcome::PackmapConflict);
    assert!(
        block_on(env.pipe.meta.get(&source, &keys::ticket(&ticket)))
            .unwrap()
            .is_some(),
        "the losing CAS must not consume its independent ticket"
    );
    let current = block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD)))
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_ref_id(&current).unwrap(), head);
}
