//! Authority-mode registration, the first-write fence and stale-generation
//! ticket replacement, over the real pipeline and a shared memory store.

use super::*;
use crate::authority::AuthorityFence;
use crate::namespace::NamespaceMode;
use crate::repo::MultiAddressing;
use crate::store::codec::{AbortReason, ReservationV1};
use crate::store::tickets::TicketCaps;
use crate::timers::registry::kinds;
use crate::upload::token::{TicketClaims, TicketKeys};
use mkit_core::upload_parts::MIN_PART_SIZE;
use std::sync::atomic::AtomicU64;

const NS: &str = "ns-a";
const OTHER: &str = "ns-b";
const SIZE: u64 = MIN_PART_SIZE + 1;

struct Generation(Arc<AtomicU64>, Arc<AtomicU32>);

impl Authorizer for Generation {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(AuthzFacts {
            authority_generation: Some(self.0.load(Ordering::SeqCst)),
            ..AuthzFacts::default()
        })
    }
}

struct Reserve;

impl Admission for Reserve {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Ok(AdmissionDecision::allow(Vec::new())
            .with_reservation(format!("r:{}", input.idempotency_key.unwrap())))
    }
}

type Fixture = Env<Hooks<Generation, Reserve>>;

struct Shared {
    kv: Arc<MemoryKv>,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    generation: Arc<AtomicU64>,
    hook_calls: Arc<AtomicU32>,
}

impl Shared {
    fn new() -> Self {
        let clock = clock();
        Self {
            kv: Arc::new(store(&clock)),
            blobs: MemoryBlobStore::default(),
            clock,
            generation: Arc::new(AtomicU64::new(0)),
            hook_calls: Arc::new(AtomicU32::new(0)),
        }
    }

    fn pipe(&self, cfg: PipelineConfig, hook: Option<ApplyHook>) -> Fixture {
        let defaults = Hooks::new();
        let hooks = Hooks {
            authorizer: Generation(self.generation.clone(), self.hook_calls.clone()),
            admission: Reserve,
            pre_receive: defaults.pre_receive,
            receipts: defaults.receipts,
            outcomes: defaults.outcomes,
        };
        let metrics = Arc::new(SpyMetrics::default());
        let spy = Spy {
            inner: self.kv.clone(),
            hook,
            ..Spy::new(MemoryKv::default())
        };
        Env {
            pipe: Pipeline::new(
                self.blobs.clone(),
                spy,
                hooks,
                cfg,
                self.clock.clone(),
                metrics.clone(),
            )
            .unwrap(),
            clock: self.clock.clone(),
            metrics,
        }
    }

    fn row(&self, namespace: &str, key: &Key) -> Option<Value> {
        now(self.kv.get(&partition(namespace), key)).unwrap()
    }
}

fn partition(namespace: &str) -> Partition {
    Partition::Namespace(NamespaceMode::Authority.namespace(namespace).unwrap().key())
}

fn config() -> PipelineConfig {
    let mut cfg = cfg(authv2());
    cfg.addressing = Addressing::Multi(MultiAddressing::new().with_namespace_policy(
        NamespacePolicy::Any {
            unsafe_without_admission: false,
        },
    ));
    cfg.namespace_mode = NamespaceMode::Authority;
    cfg.authorizer_role = AuthorizerRole::Authority;
    cfg.write_policy = WritePolicy::Owner;
    cfg.write_quota = None;
    cfg.upload_limits.max_total_bytes = 4 * MIN_PART_SIZE;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("active".into(), [7; 32])]).unwrap());
    cfg.ticket_caps = TicketCaps::new(1, 1);
    cfg.authority_fence = Some(
        AuthorityFence::parse_with_mode(
            &format!("deployment {} *", to_hex(key(8).verifying_key().as_bytes())),
            NamespaceMode::Authority,
        )
        .unwrap(),
    );
    cfg
}

fn statement(namespace: &str, generation: u64) -> String {
    let created = u64::try_from(T0).unwrap();
    let text = [
        "mkit-authority-generation:v1".to_owned(),
        "deployment".to_owned(),
        namespace.to_owned(),
        generation.to_string(),
        AUDIENCE.to_owned(),
        created.to_string(),
        (created + 60_000).to_string(),
        "ab".repeat(32),
    ]
    .join("\n");
    let signature = key(8).sign(&hash(text.as_bytes()));
    let b64 = |bytes: &[u8]| {
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    };
    format!("{}.{}", b64(text.as_bytes()), b64(&signature.to_bytes()))
}

fn register(env: &Fixture, namespace: &str, generation: u64) {
    assert_eq!(
        now(env
            .pipe
            .set_authority_generation(&statement(namespace, generation)))
        .unwrap(),
        generation
    );
}

fn request(procedure: Procedure, namespace: &str, n: u32) -> Req {
    Req::signed_for(
        &key(7),
        procedure,
        &format!("{namespace}/{REPO}"),
        b"body",
        &nonce(n),
        T0,
    )
}

fn update(env: &Fixture, namespace: &str, n: u32) -> Result<UpdateRefResult, ServerError> {
    let auth = env.auth(&request(Procedure::UpdateRef, namespace, n))?;
    now(env.pipe.update_ref(&auth, upd(HEAD, Any, A)))
}

fn begin(env: &Fixture, n: u32) -> Result<BeginUploadResult, ServerError> {
    let auth = env.auth(&request(Procedure::BeginUpload, NS, n))?;
    now(env.pipe.begin_upload(&auth, HEAD, &A, SIZE))
}

fn claims(env: &Fixture, result: BeginUploadResult) -> TicketClaims {
    let BeginUploadResult::Ticket { token, .. } = result else {
        panic!("expected a ticket")
    };
    env.pipe
        .cfg
        .ticket_keys
        .as_ref()
        .unwrap()
        .verify(&token, u64::try_from(T0).unwrap())
        .unwrap()
}

fn expect_denied(error: &ServerError, message: &str) {
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(error.public_message(), message);
}

fn ticket_keys(c: &TicketClaims) -> [Key; 5] {
    let repo = RepoName::new(REPO).unwrap();
    [
        keys::ticket(&c.ticket_id),
        keys::ticket_index(&repo, HEAD, &A, &c.signer).unwrap(),
        keys::tickets_per_ref(&repo, HEAD).unwrap(),
        keys::tickets_per_signer(&repo, HEAD, &c.signer).unwrap(),
        keys::timer(c.expires_at_ms, kinds::TICKET_EXPIRY.get(), &c.ticket_id),
    ]
}

fn reservation(shared: &Shared, rid: &str) -> ReservationV1 {
    codec::decode_reservation(
        &shared
            .row(NS, &keys::reservation(rid).unwrap())
            .expect("reservation row"),
    )
    .unwrap()
}

fn backlog_rows(shared: &Shared) -> u64 {
    shared
        .row(NS, &keys::outcome_backlog())
        .map_or(0, |value| codec::decode_backlog(&value).unwrap().rows)
}

fn registry_rows(shared: &Shared, namespace: &str) -> [bool; 3] {
    [
        keys::namespace_record(),
        keys::repo_record(&RepoName::new(REPO).unwrap()),
        keys::authority_generation(),
    ]
    .map(|key| shared.row(namespace, &key).is_some())
}

#[test]
fn a_statement_registers_a_namespace_and_unregistered_writes_are_refused() {
    let shared = Shared::new();
    let env = shared.pipe(config(), None);
    assert_eq!(
        now(env.pipe.get_authority_generation(NS)).unwrap(),
        0,
        "Get works before registration"
    );
    for refused in [
        update(&env, NS, 1).unwrap_err(),
        begin(&env, 2).unwrap_err(),
    ] {
        expect_denied(&refused, "namespace not registered");
    }
    let visibility = env
        .auth(&request(Procedure::SetRepoVisibility, NS, 3))
        .unwrap();
    expect_denied(
        &now(env.pipe.set_repo_visibility(
            &visibility,
            VisibilityRequest::Envelope(Visibility::Private),
        ))
        .unwrap_err(),
        "namespace not registered",
    );
    assert_eq!(shared.hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(registry_rows(&shared, NS), [false; 3]);
    assert!(
        shared.row(NS, &keys::lease_recovery()).is_none(),
        "a refused write persists nothing"
    );

    register(&env, NS, 0);
    // Registration creates the fence row alone: no accounting namespace.
    assert_eq!(registry_rows(&shared, NS), [false, false, true]);
    assert_eq!(update(&env, NS, 4).unwrap(), UpdateRefResult::Committed);
    assert_eq!(registry_rows(&shared, NS), [true; 3]);
    // Registration is per namespace.
    expect_denied(
        &update(&env, OTHER, 5).unwrap_err(),
        "namespace not registered",
    );
    assert_eq!(registry_rows(&shared, OTHER), [false; 3]);
}

#[test]
fn leased_sharding_refuses_unregistered_namespaces_before_admission() {
    let shared = Shared::new();
    let mut cfg = config();
    cfg.sharding = Sharding::D34;
    let env = shared.pipe(cfg, None);
    expect_denied(
        &update(&env, NS, 1).unwrap_err(),
        "namespace not registered",
    );
    assert_eq!(shared.hook_calls.load(Ordering::SeqCst), 0);
    assert_eq!(registry_rows(&shared, NS), [false; 3]);
    register(&env, NS, 0);
    assert_eq!(update(&env, NS, 2).unwrap(), UpdateRefResult::Committed);
}

#[test]
fn registering_at_a_positive_generation_also_unlocks_writes_and_never_rolls_back() {
    let shared = Shared::new();
    let env = shared.pipe(config(), None);
    register(&env, NS, 2);
    shared.generation.store(2, Ordering::SeqCst);
    assert_eq!(update(&env, NS, 1).unwrap(), UpdateRefResult::Committed);
    let rollback = now(env.pipe.set_authority_generation(&statement(NS, 0))).unwrap_err();
    expect_denied(&rollback, "authority generation step rejected");
    assert_eq!(now(env.pipe.get_authority_generation(NS)).unwrap(), 2);
}

#[test]
fn a_stale_hook_generation_is_refused_atomically_even_on_the_first_write() {
    let shared = Shared::new();
    let env = shared.pipe(config(), None);
    register(&env, NS, 2);
    shared.generation.store(1, Ordering::SeqCst);
    expect_denied(
        &update(&env, NS, 1).unwrap_err(),
        "namespace authority generation changed",
    );
    expect_denied(
        &begin(&env, 2).unwrap_err(),
        "namespace authority generation changed",
    );
    assert_eq!(
        registry_rows(&shared, NS),
        [false, false, true],
        "nothing but the registration exists"
    );
    shared.generation.store(2, Ordering::SeqCst);
    assert_eq!(update(&env, NS, 3).unwrap(), UpdateRefResult::Committed);
    // The creation batch itself is guarded by the generation it was authorized under.
    let batches = env.pipe.meta.batches.lock().unwrap();
    let creation = batches
        .iter()
        .find(|batch| {
            batch
                .preconditions
                .contains(&Precondition::Absent(keys::namespace_record()))
        })
        .expect("creation batch");
    assert!(creation.preconditions.contains(&Precondition::Equals(
        keys::authority_generation(),
        codec::encode_u64(2)
    )));
}

#[test]
fn a_generation_bump_while_the_creation_batch_is_in_flight_creates_nothing() {
    let shared = Shared::new();
    let fired = Arc::new(AtomicBool::new(false));
    let hook: ApplyHook = {
        let fired = fired.clone();
        Box::new(move |kv, p, batch| {
            if batch
                .preconditions
                .contains(&Precondition::Absent(keys::namespace_record()))
                && !fired.swap(true, Ordering::SeqCst)
            {
                now(kv.apply(
                    p,
                    Batch::new().put(keys::authority_generation(), codec::encode_u64(3)),
                ))
                .unwrap();
            }
        })
    };
    let env = shared.pipe(config(), Some(hook));
    register(&env, NS, 2);
    shared.generation.store(2, Ordering::SeqCst);
    expect_denied(
        &update(&env, NS, 1).unwrap_err(),
        "namespace authority generation changed",
    );
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(registry_rows(&shared, NS), [false, false, true]);
}

#[test]
fn self_certifying_deployments_can_register_before_their_first_write() {
    let owner = format!("ed25519-{}", to_hex(key(1).verifying_key().as_bytes()));
    let shared = Shared::new();
    let mut cfg = config();
    cfg.namespace_mode = NamespaceMode::SelfCertifying;
    cfg.authority_fence = Some(
        AuthorityFence::parse(&format!(
            "deployment {} {owner}",
            to_hex(key(8).verifying_key().as_bytes())
        ))
        .unwrap(),
    );
    let env = shared.pipe(cfg, None);
    // Previously refused until the namespace record existed.
    register(&env, &owner, 0);
    let ns = crate::NamespaceKey::from_stored(owner);
    assert!(
        now(shared
            .kv
            .get(&Partition::Namespace(ns), &keys::namespace_record()))
        .unwrap()
        .is_none()
    );
}

#[test]
fn a_bump_replaces_the_stale_ticket_at_once_with_one_aborted_outcome() {
    let shared = Shared::new();
    let env = shared.pipe(config(), None);
    register(&env, NS, 0);
    let first = claims(&env, begin(&env, 1).unwrap());
    assert_eq!(first.authority_generation, Some(0));
    assert_eq!(shared.blobs.multipart_session_count(), 1);
    // Without a bump the retry is idempotent.
    assert_eq!(
        claims(&env, begin(&env, 2).unwrap()).ticket_id,
        first.ticket_id
    );

    register(&env, NS, 1);
    shared.generation.store(1, Ordering::SeqCst);
    let second = claims(&env, begin(&env, 3).unwrap());
    assert_eq!(second.authority_generation, Some(1));
    assert_ne!(second.ticket_id, first.ticket_id);

    let (old, new) = (ticket_keys(&first), ticket_keys(&second));
    assert!(shared.row(NS, &old[0]).is_none());
    assert!(shared.row(NS, &new[0]).is_some());
    assert_eq!(
        shared.row(NS, &old[1]),
        Some(codec::encode_ref_id(&second.ticket_id))
    );
    assert!(shared.row(NS, &old[4]).is_none(), "the old timer is gone");
    assert!(shared.row(NS, &new[4]).is_some());
    // The counters stay at the cap of one, and the cap did not block the open.
    for key in &new[2..4] {
        assert_eq!(shared.row(NS, key), Some(codec::encode_u64(1)));
    }
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(1))),
        ReservationV1::Aborted {
            reason: AbortReason::EpochMismatch,
            procedure: codec::StoredProcedure::BeginUpload,
            ..
        }
    ));
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(3))),
        ReservationV1::Ticketed { ticket_id } if ticket_id == second.ticket_id
    ));
    assert_eq!(backlog_rows(&shared), 1);
    // The old multipart session was aborted after the commit.
    assert_eq!(shared.blobs.multipart_session_count(), 1);

    // The new generation's ticket is idempotent again; the old token is dead.
    assert_eq!(
        claims(&env, begin(&env, 4).unwrap()).ticket_id,
        second.ticket_id
    );
    let moved = now(env
        .pipe
        .check_ticket_generation(&partition_key(), first.authority_generation))
    .unwrap_err();
    expect_denied(&moved, "namespace authority generation changed");
}

fn partition_key() -> crate::NamespaceKey {
    NamespaceMode::Authority.namespace(NS).unwrap().key()
}

#[test]
fn a_ticket_from_a_newer_generation_than_the_hook_is_never_replaced() {
    let shared = Shared::new();
    let env = shared.pipe(config(), None);
    register(&env, NS, 1);
    shared.generation.store(1, Ordering::SeqCst);
    let ticket = claims(&env, begin(&env, 1).unwrap());
    // A hook that lags the stored ticket (a rollback) is refused, not obeyed.
    shared.generation.store(0, Ordering::SeqCst);
    expect_denied(
        &begin(&env, 2).unwrap_err(),
        "namespace authority generation changed",
    );
    assert!(shared.row(NS, &ticket_keys(&ticket)[0]).is_some());
    assert_eq!(backlog_rows(&shared), 0);
}

#[test]
fn a_consumption_that_lands_first_makes_the_replacement_open_normally() {
    let shared = Shared::new();
    let first_ticket = Arc::new(Mutex::new(None::<TicketClaims>));
    let fired = Arc::new(AtomicBool::new(false));
    let hook: ApplyHook = {
        let (first_ticket, fired) = (first_ticket.clone(), fired.clone());
        Box::new(move |kv, p, batch| {
            let Some(old) = first_ticket.lock().unwrap().clone() else {
                return;
            };
            let old_keys = ticket_keys(&old);
            if batch.writes.contains(&Write::Delete(old_keys[0].clone()))
                && !fired.swap(true, Ordering::SeqCst)
            {
                // A CompleteUpload-style consumption commits first.
                let mut consume = Batch::new();
                for key in old_keys {
                    consume = consume.delete(key);
                }
                assert_eq!(now(kv.apply(p, consume)).unwrap(), BatchOutcome::Committed);
            }
        })
    };
    let env = shared.pipe(config(), Some(hook));
    register(&env, NS, 0);
    let first = claims(&env, begin(&env, 1).unwrap());
    *first_ticket.lock().unwrap() = Some(first.clone());
    register(&env, NS, 1);
    shared.generation.store(1, Ordering::SeqCst);
    let second = claims(&env, begin(&env, 2).unwrap());
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(second.authority_generation, Some(1));
    let new = ticket_keys(&second);
    assert!(shared.row(NS, &new[0]).is_some());
    for key in &new[2..4] {
        assert_eq!(shared.row(NS, key), Some(codec::encode_u64(1)));
    }
    // The consumed ticket's reservation was not touched by the replan.
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(1))),
        ReservationV1::Ticketed { .. }
    ));
    assert_eq!(backlog_rows(&shared), 0);
}

#[test]
fn of_two_racing_replacements_one_wins_and_the_loser_aborts_cleanly() {
    let shared = Shared::new();
    let other = Arc::new(shared.pipe(config(), None));
    let first_ticket = Arc::new(Mutex::new(None::<TicketClaims>));
    let fired = Arc::new(AtomicBool::new(false));
    let hook: ApplyHook = {
        let (other, first_ticket, fired) = (other.clone(), first_ticket.clone(), fired.clone());
        Box::new(move |_, _, batch| {
            let Some(old) = first_ticket.lock().unwrap().clone() else {
                return;
            };
            if batch
                .writes
                .contains(&Write::Delete(ticket_keys(&old)[0].clone()))
                && !fired.swap(true, Ordering::SeqCst)
            {
                // A second replacement commits while the first is in flight.
                claims(&other, begin(&other, 20).unwrap());
            }
        })
    };
    let env = shared.pipe(config(), Some(hook));
    register(&env, NS, 0);
    let first = claims(&env, begin(&env, 1).unwrap());
    *first_ticket.lock().unwrap() = Some(first);
    register(&env, NS, 1);
    shared.generation.store(1, Ordering::SeqCst);
    let error = begin(&env, 2).unwrap_err();
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(error.code(), Code::Aborted);
    // The winner's ticket is the only one; the loser's reservation is aborted.
    let winner = claims(&env, begin(&env, 21).unwrap());
    let keys_now = ticket_keys(&winner);
    for key in &keys_now[2..4] {
        assert_eq!(shared.row(NS, key), Some(codec::encode_u64(1)));
    }
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(20))),
        ReservationV1::Ticketed { .. }
    ));
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(2))),
        ReservationV1::Aborted { .. }
    ));
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(1))),
        ReservationV1::Aborted {
            reason: AbortReason::EpochMismatch,
            ..
        }
    ));
    // Old and loser sessions are aborted; only the winner's remains.
    assert_eq!(shared.blobs.multipart_session_count(), 1);
    assert_eq!(backlog_rows(&shared), 2);
}

#[test]
fn a_bump_between_planning_and_commit_refuses_the_replacement_whole() {
    let shared = Shared::new();
    let first_ticket = Arc::new(Mutex::new(None::<TicketClaims>));
    let fired = Arc::new(AtomicBool::new(false));
    let hook: ApplyHook = {
        let (first_ticket, fired) = (first_ticket.clone(), fired.clone());
        Box::new(move |kv, p, batch| {
            let Some(old) = first_ticket.lock().unwrap().clone() else {
                return;
            };
            if batch
                .writes
                .contains(&Write::Delete(ticket_keys(&old)[0].clone()))
                && !fired.swap(true, Ordering::SeqCst)
            {
                now(kv.apply(
                    p,
                    Batch::new().put(keys::authority_generation(), codec::encode_u64(2)),
                ))
                .unwrap();
            }
        })
    };
    let env = shared.pipe(config(), Some(hook));
    register(&env, NS, 0);
    let first = claims(&env, begin(&env, 1).unwrap());
    *first_ticket.lock().unwrap() = Some(first.clone());
    register(&env, NS, 1);
    shared.generation.store(1, Ordering::SeqCst);
    expect_denied(
        &begin(&env, 2).unwrap_err(),
        "namespace authority generation changed",
    );
    assert!(fired.load(Ordering::SeqCst));
    // Nothing of the replacement landed: the old ticket, counters and
    // reservation are exactly as before, and the old session lives.
    let old = ticket_keys(&first);
    assert!(shared.row(NS, &old[0]).is_some());
    assert_eq!(shared.row(NS, &old[2]), Some(codec::encode_u64(1)));
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(1))),
        ReservationV1::Ticketed { .. }
    ));
    assert!(matches!(
        reservation(&shared, &format!("r:{}", nonce(2))),
        ReservationV1::Aborted {
            reason: AbortReason::EpochMismatch,
            ..
        }
    ));
    assert_eq!(shared.blobs.multipart_session_count(), 1);
}
