//! Pipeline tests over the memory stores and a `ManualClock`.

#[path = "tests_begin_parts.rs"]
mod begin_parts;
mod grants;
#[cfg(feature = "http-objects")]
mod http_objects;
mod indexed;
mod info;
mod policy;
mod ref_policy;
#[cfg(feature = "remote-hooks")]
mod remote_hooks;
mod url_token;
mod visibility;

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ed25519_dalek::{Signer, SigningKey};
use futures_executor::block_on;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::refs::RefWriteCondition::{self, Any, Match, Missing};
use mkit_core::write_auth::{Context as AuthContext, Operation as SignedOp};
use proptest::prelude::*;

use super::plan::*;
use super::*;
use crate::auth_v2::AuthV2Config;
use crate::error::Code;
use crate::memory::{MemoryBlobStore, MemoryFault, MemoryKv};
use crate::op::VerifiedAuth;
use crate::principal::Principal;
use crate::quota::{QuotaScope, QuotaState};
use crate::replay::{ReplayKey, ReplayRecord, ReplayState};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::keys::LAYOUT_VERSION;
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{
    Batch, Key, PartitionStats, Precondition, ScanPage, StoreCapabilities, Value, Write, codec,
    keys,
};
use crate::telemetry::METRIC_REQUESTS;

const AUDIENCE: &str = "https://api.example.test";
const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;
const WINDOW: u64 = 10_000;
const HEAD: &str = "refs/heads/main";
const PACKMAP: &str = "refs/mkit/packmap/main";
const A: Hash = [0xaa; 32];
const B: Hash = [0xbb; 32];
const C: Hash = [0xcc; 32];

#[test]
fn d34_relay_batch_requires_source_lease() {
    let relay = Batch::new().put(keys::relay(1), Value::default());
    assert_eq!(
        require_relay_source_lease(Sharding::D34, false, &relay)
            .unwrap_err()
            .code(),
        Code::Internal
    );
    assert!(require_relay_source_lease(Sharding::D34, true, &relay).is_ok());
    assert!(require_relay_source_lease(Sharding::Single, false, &relay).is_ok());
    assert!(require_relay_source_lease(Sharding::D34, false, &Batch::new()).is_ok());
}

fn planned_ticket_advance(count: usize) -> Batch {
    planned_ticket_advance_mode(count, true)
}

#[allow(clippy::too_many_lines)] // A full ticket snapshot and its expected maximal planner shape.
fn planned_ticket_advance_mode(count: usize, d34: bool) -> Batch {
    use crate::store::codec::{ReservationV1, TicketV1};
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let d34_shards = D34Shards;
    let single_shards = SinglePartition;
    let shards: &dyn ShardMap = if d34 { &d34_shards } else { &single_shards };
    let source = shards.ref_shard(&repo, HEAD);
    if d34 {
        assert_ne!(
            shards.ref_index(&repo, HEAD),
            shards.ref_index(&repo, PACKMAP)
        );
    }
    let signer = [7; 32];
    let reservations: Vec<_> = (0..count).map(|i| format!("s:advance-{i}")).collect();
    let ids: Vec<_> = reservations
        .iter()
        .map(|rid| crate::store::tickets::ticket_id(rid))
        .collect();
    let advance = advance::AdvanceWrite {
        ids: &ids,
        signer,
        head_ref: HEAD,
        repo_id: &repo,
        repository: REPO,
        source: &source,
        shards,
    };
    let refs = [upd(PACKMAP, Missing, B), upd(HEAD, Missing, C)];
    let replay = ReplayGuard {
        scope: [1; 32],
        fingerprint: [2; 32],
        expires_at_ms: T0 + 60_000,
    };
    let req = WriteRequest {
        authority_generation: None,
        repo: &repo.name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        ref_index: d34.then_some((&repo, &source, shards)),
        replay: Some(replay),
        charges: &[],
        namespace_charge: None,
        grant: Some(crate::op::GrantRef {
            id: [9; 32],
            epoch: u64::from(d34),
            presence_requirement: None,
        }),
        lease: d34.then_some(lease::LeaseWrite {
            value: codec::EpochLease {
                authority_generation: None,
                epoch: 1,
                expires_at_ms: ms(T0) + 30_000,
                config_version: 1,
            },
            install: true,
        }),
        layout_version: true,
        mark_repo_known: true,
        begin: None,
        advance: Some(advance.clone()),
        implicit: None,
        rejection: None,
        pending: None,
    };
    let mut snap = snapshot(&req, &[]);
    let tickets: Vec<_> = reservations
        .iter()
        .enumerate()
        .map(|(i, rid)| {
            let mut pack_id = [0; 32];
            pack_id[0] = u8::try_from(i).unwrap() << 4;
            TicketV1 {
                authority_generation: None,
                repo: repo.name.clone(),
                ref_name: HEAD.into(),
                signer,
                pack_id,
                bytes: 32,
                part_size: 8 * 1024 * 1024,
                created_at_ms: (T0 - 1_000) as u64,
                expires_at_ms: (T0 + 60_000) as u64,
                reservation_id: rid.clone(),
                upload_session: None,
            }
        })
        .collect();
    for (id, ticket) in ids.iter().zip(&tickets) {
        snap.insert(keys::ticket(id), Some(codec::encode_ticket(ticket)));
    }
    for key in advance::detail_keys(&snap, &advance).unwrap() {
        snap.insert(key, None);
    }
    for (id, ticket) in ids.iter().zip(&tickets) {
        snap.insert(
            keys::ticket_index(&repo.name, HEAD, &ticket.pack_id, &signer).unwrap(),
            Some(codec::encode_ref_id(id)),
        );
        snap.insert(
            keys::reservation(&ticket.reservation_id).unwrap(),
            Some(codec::encode_reservation(&ReservationV1::Ticketed {
                ticket_id: *id,
            })),
        );
    }
    snap.insert(
        keys::tickets_per_ref(&repo.name, HEAD).unwrap(),
        Some(codec::encode_u64(count as u64)),
    );
    snap.insert(
        keys::tickets_per_signer(&repo.name, HEAD, &signer).unwrap(),
        Some(codec::encode_u64(count as u64)),
    );
    let Planned::Apply(plan) = plan_write(&req, &snap, &clock_at(T0 as u64, None)).unwrap() else {
        panic!("expected batch")
    };
    plan.batch.validate(&StoreCapabilities::full()).unwrap();
    plan.batch
}

#[test]
fn seven_ticket_advance_plans_a_valid_real_batch() {
    let batch = planned_ticket_advance(7);
    let ops = batch.preconditions.len() + batch.writes.len();
    assert_eq!(ops, 89);
    for key in [
        keys::epoch_lease(),
        keys::layout_version(),
        keys::repo_known(&repo_name()),
    ] {
        assert!(
            batch
                .preconditions
                .iter()
                .any(|p| matches!(p, Precondition::Absent(k) if *k == key))
        );
        assert!(
            batch
                .writes
                .iter()
                .any(|w| matches!(w, Write::Put(k, _) if *k == key))
        );
    }
    assert_eq!(
        ops,
        crate::store::outbox::MAX_TICKETS_PER_ADVANCE * 9
            + crate::store::outbox::ADVANCE_SHARED_OPS
    );
    assert_eq!(
        batch
            .preconditions
            .iter()
            .filter(|p| matches!(p, Precondition::Absent(k) if *k == keys::outbox_sequence()))
            .count(),
        1
    );
    assert_eq!(
        batch
            .writes
            .iter()
            .filter(|w| matches!(w, Write::Put(k, _) if *k == keys::outbox_sequence()))
            .count(),
        1
    );
    assert_eq!(batch.writes.iter().filter(|w| matches!(w, Write::Put(k, _) if matches!(keys::parse(k), Some(keys::ParsedKey::Timer { kind: 3, .. })))).count(), 1);
    assert_eq!(batch.writes.iter().filter(|w| matches!(w, Write::Put(k, _) if matches!(keys::parse(k), Some(keys::ParsedKey::OutcomePending { .. })))).count(), 7);
    assert!(batch.writes.iter().all(|write| {
        let (Write::Put(key, _) | Write::Delete(key)) = write;
        !matches!(
            keys::parse(key),
            Some(
                keys::ParsedKey::QuotaShard(_)
                    | keys::ParsedKey::QuotaView(_)
                    | keys::ParsedKey::QuotaTotal(_)
                    | keys::ParsedKey::Timer { kind: 5, .. }
            )
        )
    }));
}

#[test]
fn single_ticket_advance_guards_the_grant_epoch() {
    let batch = planned_ticket_advance_mode(7, false);
    assert!(batch.preconditions.iter().any(|guard| matches!(guard,
        Precondition::Absent(key) if *key == keys::grant_epoch()
    )));
    assert_eq!(batch.preconditions.len() + batch.writes.len(), 78);
}

/// WP-1.15 B9's largest implicit batch: a packmap write consuming
/// `MAX_TICKETS_PER_ADVANCE` pending packs under D34, each routed to its
/// own membership shard and therefore its own relay row, plus WP-1.28b's
/// ref-index relay for the packmap name itself. 27 KV ops:
/// 6 preconditions (deadline, lease, layout, repo-known, the packmap CAS,
/// the outbox sequence) and 21 writes (lease/layout/repo-known installs,
/// the packmap ref, 7 membership puts, 8 relay rows, the relay timer and
/// the sequence put).
#[test]
fn maximal_implicit_consume_plans_a_valid_batch() {
    use crate::store::outbox::MAX_TICKETS_PER_ADVANCE;
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
            [1; 32],
        )),
        name: repo_name(),
    };
    let shards = D34Shards;
    let source = shards.ref_shard(&repo, PACKMAP);
    let packs: Vec<Hash> = (0..MAX_TICKETS_PER_ADVANCE)
        .map(|i| {
            let mut pack = [0; 32];
            pack[0] = u8::try_from(i).unwrap() << 4;
            pack[31] = u8::try_from(i).unwrap();
            pack
        })
        .collect();
    let targets: std::collections::BTreeSet<_> = packs
        .iter()
        .map(|pack| shards.membership(&repo, &crate::store::BlobKey::pack(*pack)))
        .collect();
    assert_eq!(
        targets.len(),
        packs.len(),
        "each pack must route to its own membership shard"
    );
    let refs = [upd(PACKMAP, Missing, B)];
    let implicit = ImplicitConsume {
        packs: &packs,
        repo_id: &repo,
        source: &source,
        shards: &shards,
    };
    let req = WriteRequest {
        authority_generation: None,
        repo: &repo.name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        // Production sets ref_index on every non-empty D34 ref write.
        ref_index: Some((&repo, &source, &shards)),
        replay: None,
        charges: &[],
        namespace_charge: None,
        grant: None,
        lease: Some(lease::LeaseWrite {
            value: codec::EpochLease {
                authority_generation: None,
                epoch: 1,
                expires_at_ms: ms(T0) + 30_000,
                config_version: 1,
            },
            install: true,
        }),
        layout_version: true,
        mark_repo_known: true,
        begin: None,
        advance: None,
        pending: None,
        implicit: Some(implicit),
        rejection: None,
    };
    let Planned::Apply(plan) = plan_write(&req, &snapshot(&req, &[]), &clock_at(5, None)).unwrap()
    else {
        panic!("expected a batch")
    };
    plan.batch.validate(&StoreCapabilities::full()).unwrap();
    let ops = plan.batch.preconditions.len() + plan.batch.writes.len();
    assert!(ops <= crate::store::MAX_BATCH_OPS, "{ops}");
    assert_eq!(ops, 27, "adjust the note at MAX_TICKETS_PER_ADVANCE");
    let writes_of = |wanted: fn(&keys::ParsedKey) -> bool| -> usize {
        plan.batch
            .writes
            .iter()
            .filter(|w| {
                let (Write::Put(k, _) | Write::Delete(k)) = w;
                keys::parse(k).is_some_and(|parsed| wanted(&parsed))
            })
            .count()
    };
    assert_eq!(
        writes_of(|p| matches!(p, keys::ParsedKey::Membership { .. })),
        packs.len()
    );
    // Seven membership relay rows plus the packmap name's own ref-index
    // relay row (WP-1.28b); every row stays under the puts+deletes cap.
    let relays = index_relays(&plan.batch);
    assert_eq!(relays.len(), packs.len() + 1);
    for relay in &relays {
        assert!(relay.puts.len() + relay.deletes.len() <= crate::store::outbox::MAX_RELAY_PUTS);
    }
    // No ticket, reservation or outcome rows: implicit membership carries
    // no carry-forward metadata.
    assert_eq!(
        writes_of(|p| matches!(
            p,
            keys::ParsedKey::Ticket(_)
                | keys::ParsedKey::Reservation(_)
                | keys::ParsedKey::OutcomePending { .. }
                | keys::ParsedKey::OutcomeBacklog
        )),
        0
    );
}

#[test]
fn unsigned_ticketed_advance_is_a_ticket_failure() {
    let env = env(AuthMode::Open);
    let a = env.auth(&Req::unsigned(Procedure::AdvanceRefs)).unwrap();
    let err = block_on(env.pipe.advance_refs_with_tickets(
        &a,
        upd(HEAD, Missing, A),
        upd(PACKMAP, Missing, B),
        vec![[1; 32]],
    ))
    .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "invalid or expired upload ticket");
}

#[test]
fn ticket_reservation_id_mismatch_is_corruption() {
    let repo = repo();
    let shards = SinglePartition;
    let source = shards.ref_shard(&repo, HEAD);
    let id = [3; 32];
    let ids = [id];
    let advance = advance::AdvanceWrite {
        ids: &ids,
        signer: [7; 32],
        head_ref: HEAD,
        repo_id: &repo,
        repository: REPO,
        source: &source,
        shards: &shards,
    };
    let mut snap = Snapshot::default();
    snap.insert(
        keys::ticket(&id),
        Some(codec::encode_ticket(&codec::TicketV1 {
            authority_generation: None,
            repo: repo.name.clone(),
            ref_name: HEAD.into(),
            signer: [7; 32],
            pack_id: A,
            bytes: 32,
            part_size: 8 * 1024 * 1024,
            created_at_ms: ms(T0 - 1_000),
            expires_at_ms: ms(T0 + 60_000),
            reservation_id: "s:other".into(),
            upload_session: None,
        })),
    );
    let err = advance::validate(&snap, &advance, T0).unwrap_err();
    assert_eq!(err.code(), Code::Internal);
}

#[test]
fn golden_two_ticket_advance_batch_keys() {
    use std::fmt::Write as _;
    let batch = planned_ticket_advance(2);
    let mut actual = format!(
        "ops={} pre={} writes={}\n",
        batch.preconditions.len() + batch.writes.len(),
        batch.preconditions.len(),
        batch.writes.len()
    );
    for pre in &batch.preconditions {
        match pre {
            Precondition::NotAfter(_) => actual.push_str("pre NotAfter\n"),
            Precondition::Absent(k) => {
                writeln!(actual, "pre Absent {}", to_hex_bytes(k.as_bytes())).unwrap();
            }
            Precondition::Present(k) => {
                writeln!(actual, "pre Present {}", to_hex_bytes(k.as_bytes())).unwrap();
            }
            Precondition::Equals(k, _) => {
                writeln!(actual, "pre Equals {}", to_hex_bytes(k.as_bytes())).unwrap();
            }
        }
    }
    for write in &batch.writes {
        match write {
            Write::Put(k, _) => writeln!(actual, "put {}", to_hex_bytes(k.as_bytes())).unwrap(),
            Write::Delete(k) => writeln!(actual, "delete {}", to_hex_bytes(k.as_bytes())).unwrap(),
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/server/advance-two-ticket-batch.txt");
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), actual);
}

// ---------------------------------------------------------------- helpers

/// Run a future that never waits (memory stores) to completion.
fn now<F: Future>(fut: F) -> F::Output {
    match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("memory store future pending"),
    }
}

/// Pending once, then ready: makes every store call a real await point.
#[derive(Default)]
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

type AfterApplyHook = Box<dyn Fn(&MemoryKv, &Partition, &Batch, &BatchOutcome) + Send + Sync>;

type ApplyHook = Box<dyn Fn(&MemoryKv, &Partition, &Batch) + Send + Sync>;

/// A `MemoryKv` that records every key it sees and batch it applies, can
/// run a hook before each apply, can yield at every call and can fail
/// every read.
struct Spy {
    inner: Arc<MemoryKv>,
    hook: Option<ApplyHook>,
    after_hook: Option<AfterApplyHook>,
    yields: bool,
    fail_reads: bool,
    seen: Mutex<Vec<Key>>,
    ops: Mutex<Vec<&'static str>>,
    batches: Mutex<Vec<Batch>>,
    calls: AtomicU32,
    fail_next_apply: Arc<AtomicBool>,
}

impl Spy {
    fn new(inner: MemoryKv) -> Self {
        Self {
            inner: Arc::new(inner),
            hook: None,
            after_hook: None,
            yields: false,
            fail_reads: false,
            seen: Mutex::default(),
            ops: Mutex::default(),
            batches: Mutex::default(),
            calls: AtomicU32::new(0),
            fail_next_apply: Arc::new(AtomicBool::new(false)),
        }
    }

    fn hook(
        mut self,
        hook: impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync + 'static,
    ) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }

    /// Every `get`/`get_many`/`scan` fails.
    fn failing_reads(mut self) -> Self {
        self.fail_reads = true;
        self
    }

    /// Backend round trips so far.
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Keys seen, in call order.
    fn seen(&self) -> Vec<Key> {
        self.seen.lock().unwrap().clone()
    }

    /// Operation kinds seen, in call order.
    fn ops(&self) -> Vec<&'static str> {
        self.ops.lock().unwrap().clone()
    }

    async fn pause(&self, op: &'static str) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.ops.lock().unwrap().push(op);
        if self.yields {
            YieldOnce::default().await;
        }
    }

    fn saw(&self, key: &Key) {
        self.seen.lock().unwrap().push(key.clone());
    }

    fn maybe_fail_read(&self) -> Result<(), StoreError> {
        if self.fail_reads {
            return Err(StoreError::unavailable("injected read fault"));
        }
        Ok(())
    }
}

impl NamespaceStore for Spy {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.pause("get").await;
        self.maybe_fail_read()?;
        self.saw(key);
        self.inner.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.pause("get_many").await;
        self.maybe_fail_read()?;
        for k in keys {
            self.saw(k);
        }
        self.inner.get_many(p, keys).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&crate::store::Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.pause("scan").await;
        self.maybe_fail_read()?;
        self.saw(start);
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.pause("apply").await;
        for pre in &batch.preconditions {
            if let Precondition::Absent(k) | Precondition::Present(k) | Precondition::Equals(k, _) =
                pre
            {
                self.saw(k);
            }
        }
        for write in &batch.writes {
            let (Write::Put(k, _) | Write::Delete(k)) = write;
            self.saw(k);
        }
        self.batches.lock().unwrap().push(batch.clone());
        if let Some(hook) = &self.hook {
            hook(&self.inner, p, &batch);
        }
        if self.fail_next_apply.swap(false, Ordering::SeqCst) {
            return Err(StoreError::unavailable("injected apply failure"));
        }
        let outcome = self.inner.apply(p, batch.clone()).await?;
        if let Some(hook) = &self.after_hook {
            hook(&self.inner, p, &batch, &outcome);
        }
        Ok(outcome)
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

type Labels = Vec<(String, String)>;

#[derive(Default)]
struct SpyMetrics(Mutex<Vec<(&'static str, Labels)>>);

impl Metrics for SpyMetrics {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], _by: u64) {
        let labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()));
        self.0.lock().unwrap().push((name, labels.collect()));
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}

impl SpyMetrics {
    fn count(&self, name: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| *n == name)
            .count()
    }
}

struct Env<H = Hooks> {
    pipe: Pipeline<MemoryBlobStore, Spy, H>,
    clock: Arc<ManualClock>,
    metrics: Arc<SpyMetrics>,
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    }
}

fn ns() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

#[test]
fn single_sharding_watermark_reads_namespace_outbox() {
    let env = env(AuthMode::Open);
    let namespace = NamespaceKey::deployment_default();
    assert_eq!(
        now(env.pipe.namespace_relay_watermark(&namespace)).unwrap(),
        u64::try_from(T0).unwrap()
    );
    let row = codec::RelayV1 {
        at_ms: u64::try_from(T0).unwrap() - 5,
        target: ns(),
        puts: vec![(Key::new(&b"x\0"[..]), Value::default())],
        deletes: Vec::new(),
    };
    now(env.pipe.meta.apply(
        &ns(),
        Batch::new().put(keys::relay(1), codec::encode_relay(&row).unwrap()),
    ))
    .unwrap();
    assert_eq!(
        now(env.pipe.namespace_relay_watermark(&namespace)).unwrap(),
        u64::try_from(T0).unwrap() - 6
    );
    let shards = now(env.pipe.active_shards(&namespace, None, 1)).unwrap();
    assert_eq!(shards.shards, vec![ns()]);
    now(env.pipe.meta.apply(
        &ns(),
        Batch::new().put(
            keys::lease_recovery(),
            codec::encode_lease_recovery(&codec::LeaseRecovery {
                resumed_at_ms: u64::try_from(T0).unwrap(),
            }),
        ),
    ))
    .unwrap();
    assert_eq!(
        now(env.pipe.namespace_relay_watermark(&namespace))
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
}

#[cfg(feature = "test-faults")]
#[test]
fn relay_delay_directive_commits_with_ref_write() {
    let env = env(AuthMode::Open);
    let req = Req::unsigned(Procedure::UpdateRef).header(RELAY_DELAY_MS_HEADER, "10000");
    assert_eq!(
        env.update(&req, &upd(HEAD, Missing, A)).unwrap(),
        UpdateRefResult::Committed
    );
    let marker = now(env.pipe.meta.get(&ns(), &faults::relay_delay_key()))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_u64(&marker).unwrap(),
        u64::try_from(T0).unwrap() + 10_000
    );
}

#[cfg(feature = "test-faults")]
#[test]
fn relay_delay_directive_commits_with_advance() {
    let env = env(AuthMode::Open);
    let req = Req::unsigned(Procedure::AdvanceRefs).header(RELAY_DELAY_MS_HEADER, "10000");
    env.advance(&req, &upd(HEAD, Missing, A), &upd(PACKMAP, Missing, B))
        .unwrap();
    let marker = now(env.pipe.meta.get(&ns(), &faults::relay_delay_key()))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_u64(&marker).unwrap(),
        u64::try_from(T0).unwrap() + 10_000
    );
}

fn authv2() -> AuthMode {
    AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap())
}

fn cfg(auth: AuthMode) -> PipelineConfig {
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    PipelineConfig::new(Addressing::Single { repo: repo() }, auth, limits)
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(T0))
}

fn store(clock: &Arc<ManualClock>) -> MemoryKv {
    MemoryKv::with_clock(clock.clone())
}

fn build<H: HookSet>(
    mut cfg: PipelineConfig,
    meta: Spy,
    hooks: H,
    clock: Arc<ManualClock>,
) -> Env<H> {
    if matches!(cfg.auth, AuthMode::AuthV2(_))
        && (!hooks.admission().is_default() || matches!(cfg.addressing, Addressing::Multi(_)))
    {
        cfg.ticket_keys.get_or_insert_with(|| {
            crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap()
        });
    }
    let metrics = Arc::new(SpyMetrics::default());
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta,
        hooks,
        cfg,
        clock.clone(),
        metrics.clone(),
    )
    .unwrap();
    Env {
        pipe,
        clock,
        metrics,
    }
}

fn env(auth: AuthMode) -> Env {
    let clock = clock();
    build(cfg(auth), Spy::new(store(&clock)), Hooks::new(), clock)
}

fn upd(name: &str, condition: RefWriteCondition, new: Hash) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        condition,
        new: Some(new),
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn nonce(n: u32) -> String {
    format!("{n:064x}")
}

/// A request as a binding would present it.
#[derive(Clone)]
struct Req {
    procedure: Procedure,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
    principal: Option<Principal>,
}

impl Req {
    fn unsigned(procedure: Procedure) -> Self {
        Self {
            procedure,
            body: Vec::new(),
            headers: Vec::new(),
            principal: None,
        }
    }

    fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.retain(|(n, _)| *n != name);
        self.headers.push((name, value.to_owned()));
        self
    }

    /// Signed with auth v2 at `created`, valid for 300 s.
    fn signed(
        key: &SigningKey,
        procedure: Procedure,
        body: &[u8],
        nonce: &str,
        created: i64,
    ) -> Self {
        Self::signed_for(key, procedure, REPO, body, nonce, created)
    }

    /// Signed with auth v2 for `repository` (a Multi wire identity) at
    /// `created`, valid for 300 s.
    fn signed_for(
        key: &SigningKey,
        procedure: Procedure,
        repository: &str,
        body: &[u8],
        nonce: &str,
        created: i64,
    ) -> Self {
        let digest = to_hex(&hash(body));
        let commitment = format!("body:{digest}");
        let mut req = Self::committed_for(key, procedure, repository, &commitment, nonce, created);
        req.body = body.to_vec();
        req.header("x-digest", &digest)
    }

    /// Signed over `commitment` at `created`, valid for 300 s, no body.
    fn committed(
        key: &SigningKey,
        procedure: Procedure,
        commitment: &str,
        nonce: &str,
        created: i64,
    ) -> Self {
        Self::committed_for(key, procedure, REPO, commitment, nonce, created)
    }

    /// Signed over `commitment` for `repository` at `created`, valid for
    /// 300 s, no body.
    fn committed_for(
        key: &SigningKey,
        procedure: Procedure,
        repository: &str,
        commitment: &str,
        nonce: &str,
        created: i64,
    ) -> Self {
        let expires = created + 300_000;
        let op = SignedOp {
            context: AuthContext {
                audience: AUDIENCE,
                repository,
            },
            procedure: procedure.connect_path(),
            commitment,
            created_at: created,
            expires_at: expires,
            nonce,
        };
        let signature = key.sign(&op.digest().unwrap());
        let headers = vec![
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", AUDIENCE.to_owned()),
            ("x-repository", repository.to_owned()),
            ("x-public-key", to_hex(key.verifying_key().as_bytes())),
            ("x-signature", to_hex_bytes(&signature.to_bytes())),
            ("x-content-commitment", commitment.to_owned()),
            ("x-created-at", created.to_string()),
            ("x-expires-at", expires.to_string()),
            ("idempotency-key", nonce.to_owned()),
        ];
        Self {
            procedure,
            body: Vec::new(),
            headers,
            principal: None,
        }
    }

    /// A signed `UpdateRef` whose body stands for `u`.
    fn update(key: &SigningKey, n: u32, u: &RefUpdate, created: i64) -> Self {
        let body = format!("{u:?}");
        Self::signed(
            key,
            Procedure::UpdateRef,
            body.as_bytes(),
            &nonce(n),
            created,
        )
    }
}

impl<H: HookSet> Env<H> {
    fn auth(&self, req: &Req) -> Result<Authenticated, ServerError> {
        let lookup = |name: &str| {
            req.headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        };
        self.pipe.authenticate(&RequestMeta {
            procedure: req.procedure,
            header: &lookup,
            header_values: None,
            unary_body: Some(&req.body),
            transport_principal: req.principal.clone(),
        })
    }

    fn update(&self, req: &Req, u: &RefUpdate) -> Result<UpdateRefResult, ServerError> {
        block_on(self.pipe.update_ref(&self.auth(req)?, u.clone()))
    }

    fn advance(
        &self,
        req: &Req,
        head: &RefUpdate,
        pm: &RefUpdate,
    ) -> Result<AdvanceOutcome, ServerError> {
        block_on(
            self.pipe
                .advance_refs(&self.auth(req)?, head.clone(), pm.clone()),
        )
    }

    fn open_update(&self, u: &RefUpdate) -> Result<UpdateRefResult, ServerError> {
        self.update(&Req::unsigned(Procedure::UpdateRef), u)
    }

    fn read(&self, name: &str) -> Option<Hash> {
        let a = self.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
        block_on(self.pipe.read_ref(&a, name)).unwrap()
    }

    fn rows(&self) -> Vec<(Key, Value)> {
        let (start, end) = (Key::new(vec![0]), Key::new(vec![0xff]));
        now(self
            .pipe
            .meta
            .inner
            .scan(&ns(), &start, &end, None, 100_000))
        .unwrap()
        .entries
    }

    fn count(&self, tag: &str) -> usize {
        let prefix = format!("{tag}\0");
        let rows = self.rows();
        rows.iter()
            .filter(|(k, _)| k.as_bytes().starts_with(prefix.as_bytes()))
            .count()
    }

    fn batches(&self) -> Vec<Batch> {
        self.pipe.meta.batches.lock().unwrap().clone()
    }
}

/// Seed refs through the store directly, one batch each.
fn seed(kv: &MemoryKv, refs: &[(&str, Hash)]) {
    let name = RepoName::new(REPO).unwrap();
    for (n, id) in refs {
        let batch = Batch::new().put(keys::ref_key(&name, n), codec::encode_ref_id(id));
        assert_eq!(
            now(kv.apply(&ns(), batch)).unwrap(),
            BatchOutcome::Committed
        );
    }
}

fn with_admission<Ad: Admission>(admission: Ad) -> Hooks<OpenAuthorizer, Ad> {
    Hooks {
        authorizer: OpenAuthorizer,
        admission,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    }
}

fn replay_row(env: &Env, req: &Req) -> Option<crate::replay::ReplayRecord> {
    let scope = env.auth(req).unwrap().auth.unwrap().replay_scope;
    now(read::replay_lookup(
        env.pipe.meta.inner.as_ref(),
        &ns(),
        &ReplayKey(scope),
    ))
    .unwrap()
}

/// The first nonce from `from` whose replay scope is (or is not) sampled
/// for pruning.
fn nonce_where<H: HookSet>(env: &Env<H>, k: &SigningKey, sampled: bool, from: u32) -> u32 {
    let u = upd(HEAD, Missing, A);
    (from..from + 1_000)
        .find(|n| {
            let scope = env
                .auth(&Req::update(k, *n, &u, T0))
                .unwrap()
                .auth
                .unwrap()
                .replay_scope;
            scope[0].is_multiple_of(plan::PRUNE_SAMPLE) == sampled
        })
        .unwrap()
}

fn code<T: core::fmt::Debug>(r: Result<T, ServerError>) -> Code {
    r.unwrap_err().code()
}

// ------------------------------------------------------------- auth v2

#[test]
fn authv2_update_ref_happy_path_then_replay_returns_same_after_ref_moved() {
    let env = env(authv2());
    let k = key(7);
    let create = upd(HEAD, Missing, A);
    let first = Req::update(&k, 1, &create, T0);
    assert_eq!(
        env.update(&first, &create).unwrap(),
        UpdateRefResult::Committed
    );
    let moved = upd(HEAD, Match(A), B);
    let second = Req::update(&k, 2, &moved, T0);
    assert_eq!(
        env.update(&second, &moved).unwrap(),
        UpdateRefResult::Committed
    );
    env.clock.advance(1_000);
    // The replay returns the saved result and repeats nothing.
    assert_eq!(
        env.update(&first, &create).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(env.read(HEAD), Some(B));
    // A conflict is stored too, and replayed as the same conflict.
    let stale = upd(HEAD, Match(A), C);
    let third = Req::update(&k, 3, &stale, T0);
    let conflict = UpdateRefResult::Conflict { current: Some(B) };
    assert_eq!(env.update(&third, &stale).unwrap(), conflict);
    let again = upd(HEAD, Match(B), C);
    assert_eq!(
        env.update(&Req::update(&k, 4, &again, T0), &again).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(env.update(&third, &stale).unwrap(), conflict);
    assert_eq!(env.read(HEAD), Some(C));
}

#[test]
fn authv2_nonce_reuse_different_op_is_invalid_argument() {
    let env = env(authv2());
    let k = key(7);
    let one = upd(HEAD, Missing, A);
    env.update(&Req::update(&k, 1, &one, T0), &one).unwrap();
    let other = upd(HEAD, Any, B);
    let err = env
        .update(&Req::update(&k, 1, &other, T0), &other)
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "nonce reused for a different operation"
    );
    assert_eq!(env.read(HEAD), Some(A));
}

#[test]
fn authv2_missing_headers_is_unauthenticated() {
    let env = env(authv2());
    for procedure in [
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::UploadPack,
    ] {
        assert_eq!(
            code(env.auth(&Req::unsigned(procedure))),
            Code::Unauthenticated
        );
    }
    let u = upd(HEAD, Missing, A);
    let signed = Req::update(&key(7), 1, &u, T0).header("x-signature", "");
    assert_eq!(code(env.update(&signed, &u)), Code::Unauthenticated);
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_wrong_audience_unauthenticated() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0).header("x-audience", "https://other.example.test");
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(
        err.public_message(),
        "request audience or repository mismatch"
    );
}

#[test]
fn authv2_expired_unauthenticated() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    env.clock.set(T0 + 300_001);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(err.public_message(), "expired or future authorization");
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_reads_need_no_signature() {
    let env = env(authv2());
    seed(env.pipe.meta.inner.as_ref(), &[(HEAD, A)]);
    let list = env.auth(&Req::unsigned(Procedure::ListRefs)).unwrap();
    assert_eq!(
        (&list.principal, &list.auth),
        (&Principal::Anonymous, &None)
    );
    let refs = block_on(env.pipe.list_refs(&list, "refs/heads/")).unwrap();
    assert_eq!(
        refs,
        vec![RefEntry {
            name: "main".into(),
            id: A
        }]
    );
    assert_eq!(env.read(HEAD), Some(A));
    let exists = env.auth(&Req::unsigned(Procedure::PackExists)).unwrap();
    assert!(!block_on(env.pipe.pack_exists(&exists, PackKey::new(C))).unwrap());
    // Credentials are bound to their procedure.
    assert_eq!(
        code(block_on(env.pipe.read_ref(&list, HEAD))),
        Code::Unauthenticated
    );
}

/// The golden `auth-v2/read.json` fixture entry as a `Req` at `created_at + 1`.
fn golden_read(index: usize) -> (Req, serde_json::Value) {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/golden/auth-v2/read.json")).unwrap();
    let fixture = fixtures[index].clone();
    let field = |name: &str| fixture[name].as_str().unwrap().to_owned();
    let unhex = |hex: &str| {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let req = Req {
        procedure: Procedure::from_connect_path(&field("procedure")).unwrap(),
        body: unhex(&field("body_hex")),
        headers: vec![
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", field("audience")),
            ("x-repository", field("repository")),
            ("x-public-key", field("public_key")),
            ("x-signature", field("signature")),
            ("x-digest", field("body_digest")),
            ("x-content-commitment", field("commitment")),
            (
                "x-created-at",
                fixture["created_at"].as_i64().unwrap().to_string(),
            ),
            (
                "x-expires-at",
                fixture["expires_at"].as_i64().unwrap().to_string(),
            ),
            ("idempotency-key", field("nonce")),
        ],
        principal: None,
    };
    (req, fixture)
}

/// An `AuthV2` pipeline routed by `X-Repository` (the read fixtures carry
/// a namespaced `ed25519-…/name` identity).
fn multi_env() -> Env {
    use crate::repo::MultiAddressing;

    let clock = clock();
    let mut config = cfg(authv2());
    config.addressing = Addressing::Multi(MultiAddressing::new());
    config.write_policy = WritePolicy::Owner;
    build(config, Spy::new(store(&clock)), Hooks::new(), clock)
}

#[test]
fn authv2_signed_reads_verify_in_full() {
    let env = env(authv2());
    let reads = [
        Procedure::ListRefs,
        Procedure::ReadRef,
        Procedure::PackExists,
        Procedure::DownloadPack,
        Procedure::GetReceipt,
    ];
    for (i, procedure) in reads.into_iter().enumerate() {
        // DownloadPack commits to its framed body `0x00‖be32(len)‖msg`;
        // at stage 0 the binding supplies it as `unary_body`.
        let body = b"request".to_vec();
        let req = Req::signed(
            &key(5),
            procedure,
            &body,
            &nonce(10 + u32::try_from(i).unwrap()),
            T0,
        );
        let a = env.auth(&req).unwrap();
        assert!(
            matches!(a.principal, Principal::Signer { .. }),
            "{procedure:?}"
        );
        assert!(a.auth.is_some(), "{procedure:?}");
    }
    // A signed read captures a presented grant (Multi scope, §4.2); an
    // unsigned read stays anonymous and never signs out a replay record.
    let granted = Req::signed(&key(5), Procedure::ReadRef, b"x", &nonce(30), T0)
        .header("x-write-grant", "scheme.body");
    assert!(env.auth(&granted).unwrap().write_grant.is_some());
    let reads = [
        Procedure::ListRefs,
        Procedure::ReadRef,
        Procedure::PackExists,
        Procedure::DownloadPack,
        Procedure::GetReceipt,
    ];
    let before = (env.count("p"), env.count("px"));
    for procedure in reads {
        let a = env
            .auth(&Req::signed(&key(5), procedure, b"r", &nonce(40), T0))
            .unwrap();
        assert_ne!(a.principal, Principal::Anonymous, "{procedure:?}");
    }
    assert_eq!((env.count("p"), env.count("px")), before);
}

#[test]
fn authv2_signed_read_failures_never_fall_back_to_anonymous() {
    let env = env(authv2());
    // A marker header without the rest of the envelope.
    let marker_only = Req::unsigned(Procedure::ReadRef).header("x-signature", "ab");
    assert_eq!(code(env.auth(&marker_only)), Code::Unauthenticated);
    // Empty marker value still marks the request signed.
    let empty_marker = Req::unsigned(Procedure::ListRefs).header("x-envelope-version", "");
    assert_eq!(code(env.auth(&empty_marker)), Code::Unauthenticated);
    // A wrong signature, a tampered body, an expired envelope.
    let forged = Req::signed(&key(5), Procedure::ReadRef, b"x", &nonce(50), T0)
        .header("x-signature", &"ff".repeat(64));
    assert_eq!(code(env.auth(&forged)), Code::Unauthenticated);
    let mut tampered = Req::signed(&key(5), Procedure::ListRefs, b"x", &nonce(51), T0);
    tampered.body = b"other".to_vec();
    assert_eq!(code(env.auth(&tampered)), Code::Unauthenticated);
    let expired = Req::signed(&key(5), Procedure::ReadRef, b"x", &nonce(52), T0 - 400_000);
    assert_eq!(code(env.auth(&expired)), Code::Unauthenticated);
    // Unsigned reads still pass anonymously; IssueObjectUrl never does.
    for procedure in [Procedure::ListRefs, Procedure::SetRepoVisibility] {
        assert_eq!(
            env.auth(&Req::unsigned(procedure)).unwrap().principal,
            Principal::Anonymous,
            "{procedure:?}"
        );
    }
    assert_eq!(
        code(env.auth(&Req::unsigned(Procedure::IssueObjectUrl))),
        Code::Unauthenticated
    );
}

#[test]
fn multi_signed_read_scopes_to_the_resolved_repository() {
    use mkit_core::repo_identity::Namespace;

    let env = multi_env();
    let signer = key(5).verifying_key().to_bytes();
    let identity = format!("{}/{}", Namespace::Ed25519(signer), REPO);
    let good = Req::signed_for(
        &key(5),
        Procedure::ListRefs,
        &identity,
        b"r",
        &nonce(60),
        T0,
    );
    let a = env.auth(&good).unwrap();
    assert!(matches!(a.principal, Principal::Signer { .. }));
    assert_eq!(a.repo().identity, identity);
    // The same envelope sent for another repository identity fails.
    let moved = good.clone().header("x-repository", &format!("{identity}x"));
    assert_eq!(code(env.auth(&moved)), Code::Unauthenticated);
}

#[test]
fn golden_signed_reads_verify_at_stage_0() {
    let env = multi_env();
    for index in [0usize, 1] {
        let (req, fixture) = golden_read(index);
        env.clock.set(fixture["created_at"].as_i64().unwrap() + 1);
        let a = env.auth(&req).unwrap();
        assert!(matches!(a.principal, Principal::Signer { .. }));
        assert_eq!(
            to_hex(&a.auth.unwrap().signer),
            fixture["public_key"].as_str().unwrap(),
            "entry {index}"
        );
    }
    env.clock.set(T0);
    // Forging the signature on the DownloadPack frame fails.
    let (req, _) = golden_read(1);
    let forged = req.header("x-signature", &"ff".repeat(64));
    assert_eq!(code(env.auth(&forged)), Code::Unauthenticated);
}

#[test]
fn quota_exhaustion_is_resource_exhausted_and_allocates_no_replay_record() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 2,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let k = key(7);
    let reqs: Vec<_> = (1..=3)
        .map(|i| {
            let u = upd(&format!("refs/heads/b{i}"), Missing, A);
            (Req::update(&k, i, &u, T0), u)
        })
        .collect();
    env.update(&reqs[0].0, &reqs[0].1).unwrap();
    env.update(&reqs[1].0, &reqs[1].1).unwrap();
    let rows = env.rows();
    let err = env.update(&reqs[2].0, &reqs[2].1).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        err.public_message(),
        "write op quota exceeded for this window; try again later"
    );
    assert_eq!(replay_row(&env, &reqs[2].0), None);
    assert_eq!(env.rows(), rows, "nothing allocated");
}

#[test]
fn retry_after_quota_exhaustion_still_returns_stored_result() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 1,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let k = key(7);
    let first = upd(HEAD, Missing, A);
    let req = Req::update(&k, 1, &first, T0);
    env.update(&req, &first).unwrap();
    let next = upd(HEAD, Any, B);
    assert_eq!(
        code(env.update(&Req::update(&k, 2, &next, T0), &next)),
        Code::ResourceExhausted
    );
    // The saved reply is checked before admission.
    assert_eq!(
        env.update(&req, &first).unwrap(),
        UpdateRefResult::Committed
    );
}

#[test]
fn namespace_denial_before_lease_allocates_nothing_and_replay_stays_free() {
    use crate::repo::MultiAddressing;

    let signer = [7; 32];
    let namespace = Namespace::Ed25519(signer);
    let clock = clock();
    let mut config = cfg(AuthMode::Open);
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.sharding = Sharding::D34;
    config.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 2,
        max_bytes: 0,
    });
    let env = build(config, Spy::new(store(&clock)), Hooks::new(), clock);
    let identity = format!("{namespace}/{REPO}");
    let request = Req::unsigned(Procedure::UpdateRef).header("x-repository", &identity);
    let mut a = env.auth(&request).unwrap();
    a.principal = Principal::Signer { ed25519: signer };
    a.auth = Some(VerifiedAuth {
        signer,
        replay_scope: [3; 32],
        fingerprint: [4; 32],
        nonce: nonce(1),
        commitment: crate::op::Commitment::Body(A),
        expires_at_ms: T0 + 300_000,
        created_at_ms: 0,
    });
    let ref_name = "refs/heads/fresh";
    let shard = env.pipe.shards.ref_shard(&a.repo().repo, ref_name);
    let coordinator = env.pipe.shards.coordinator(&a.repo().repo.namespace);
    let window = crate::quota::namespace_window(T0, 60_000);
    seed_namespace_view(env.pipe.meta.inner.as_ref(), &shard, window, 2, 0);
    let before = now(env.pipe.meta.inner.stats(&shard)).unwrap();
    let err = now(env.pipe.update_ref(&a, upd(ref_name, Missing, A))).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        err.public_message(),
        "namespace write op/byte quota exceeded for this window; try again later"
    );
    assert_eq!(now(env.pipe.meta.inner.stats(&shard)).unwrap(), before);
    assert_eq!(
        now(env.pipe.meta.inner.stats(&coordinator)).unwrap().keys,
        Some(0)
    );
    assert!(env.batches().is_empty(), "no lease, replay, or quota batch");

    assert!(
        now(env.pipe.meta.inner.get(&shard, &keys::replay(&[3; 32])))
            .unwrap()
            .is_none()
    );
    seed_namespace_view(env.pipe.meta.inner.as_ref(), &shard, window, 0, 0);
    let update = upd(ref_name, Missing, A);
    assert_eq!(
        now(env.pipe.update_ref(&a, update.clone())).unwrap(),
        UpdateRefResult::Committed
    );
    let counter = keys::quota_shard(window);
    let charged = now(env.pipe.meta.inner.get(&shard, &counter)).unwrap();
    seed_namespace_view(env.pipe.meta.inner.as_ref(), &shard, window, 2, 1);
    assert_eq!(
        now(env.pipe.update_ref(&a, update)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        now(env.pipe.meta.inner.get(&shard, &counter)).unwrap(),
        charged
    );
}

#[test]
fn fresh_shard_uses_coordinator_total_in_lease_read_and_persists_view() {
    use crate::repo::MultiAddressing;

    let signer = [7; 32];
    let namespace = Namespace::Ed25519(signer);
    let clock = clock();
    let mut config = cfg(AuthMode::Open);
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.sharding = Sharding::D34;
    config.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 2,
        max_bytes: 0,
    });
    let env = build(config, Spy::new(store(&clock)), Hooks::new(), clock);
    let identity = format!("{namespace}/{REPO}");
    let request = Req::unsigned(Procedure::UpdateRef).header("x-repository", &identity);
    let mut a = env.auth(&request).unwrap();
    a.principal = Principal::Signer { ed25519: signer };
    a.auth = Some(VerifiedAuth {
        signer,
        replay_scope: [3; 32],
        fingerprint: [4; 32],
        nonce: nonce(1),
        commitment: crate::op::Commitment::Body(A),
        expires_at_ms: T0 + 300_000,
        created_at_ms: 0,
    });
    let ref_name = "refs/heads/new-shard";
    let shard = env.pipe.shards.ref_shard(&a.repo().repo, ref_name);
    let coordinator = env.pipe.shards.coordinator(&a.repo().repo.namespace);
    let window = crate::quota::namespace_window(T0, 60_000);
    let qt = keys::quota_total(window);
    now(env.pipe.meta.inner.apply(
        &coordinator,
        Batch::new().put(
            qt.clone(),
            codec::encode_namespace_usage(crate::quota::NamespaceUsage { ops: 2, bytes: 0 }),
        ),
    ))
    .unwrap();
    let update = upd(ref_name, Missing, A);
    let err = now(env.pipe.update_ref(&a, update.clone())).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        env.pipe.meta.calls(),
        3,
        "read-ahead, source relay scan, and lease get_many"
    );
    assert!(env.pipe.meta.seen.lock().unwrap().contains(&qt));
    assert!(
        env.batches().is_empty(),
        "denial allocated no lease or ref state"
    );
    assert_eq!(
        now(env.pipe.meta.inner.stats(&shard)).unwrap().keys,
        Some(0)
    );

    now(env.pipe.meta.inner.apply(
        &coordinator,
        Batch::new().put(
            qt,
            codec::encode_namespace_usage(crate::quota::NamespaceUsage { ops: 1, bytes: 0 }),
        ),
    ))
    .unwrap();
    let before = env.pipe.meta.calls();
    assert_eq!(
        now(env.pipe.update_ref(&a, update)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.pipe.meta.calls() - before,
        5,
        "new shard adds one source relay scan"
    );
    let stored = now(env.pipe.meta.inner.get(&shard, &keys::quota_view(window)))
        .unwrap()
        .expect("accepted first write seeds a durable view");
    let view = codec::decode_namespace_view(&stored).unwrap();
    assert_eq!(view.total.ops, 1);
    assert_eq!(view.pushed.ops, 0);
}

fn seed_namespace_view(store: &MemoryKv, shard: &Partition, window: u64, total: u64, pushed: u64) {
    now(store.apply(
        shard,
        Batch::new().put(
            keys::quota_view(window),
            codec::encode_namespace_view(crate::quota::NamespaceView {
                total: crate::quota::NamespaceUsage {
                    ops: total,
                    bytes: 0,
                },
                pushed: crate::quota::NamespaceUsage {
                    ops: pushed,
                    bytes: 0,
                },
                observed_at_ms: T0 as u64,
            }),
        ),
    ))
    .expect("seed quota view");
}

#[test]
fn namespace_race_after_lease_is_retryable_instead_of_a_late_denial() {
    use crate::repo::MultiAddressing;

    let signer = [7; 32];
    let namespace = Namespace::Ed25519(signer);
    let clock = clock();
    let mut config = cfg(AuthMode::Open);
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.sharding = Sharding::D34;
    config.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 2,
        max_bytes: 0,
    });
    let window = crate::quota::namespace_window(T0, 60_000);
    let shard = Partition::Ref {
        ns: NamespaceKey::from_namespace(&namespace),
        repo: RepoName::new(REPO).unwrap(),
        shard_ref: HEAD.to_owned(),
    };
    let raced_shard = shard.clone();
    let injected = Arc::new(AtomicBool::new(false));
    let once = injected.clone();
    let mut meta = Spy::new(store(&clock));
    meta.after_hook = Some(Box::new(move |store, partition, _batch, outcome| {
        if !matches!(partition, Partition::Coordinator(_))
            || !matches!(outcome, BatchOutcome::Committed)
            || once.swap(true, Ordering::SeqCst)
        {
            return;
        }
        now(store.apply(
            &raced_shard,
            Batch::new().put(
                keys::quota_shard(window),
                codec::encode_namespace_usage(crate::quota::NamespaceUsage { ops: 2, bytes: 0 }),
            ),
        ))
        .unwrap();
    }));
    let env = build(config, meta, Hooks::new(), clock);
    let identity = format!("{namespace}/{REPO}");
    let request = Req::unsigned(Procedure::UpdateRef).header("x-repository", &identity);
    let mut a = env.auth(&request).unwrap();
    a.principal = Principal::Signer { ed25519: signer };
    a.auth = Some(VerifiedAuth {
        signer,
        replay_scope: [3; 32],
        fingerprint: [4; 32],
        nonce: nonce(1),
        commitment: crate::op::Commitment::Body(A),
        expires_at_ms: T0 + 300_000,
        created_at_ms: 0,
    });
    assert_eq!(env.pipe.shards.ref_shard(&a.repo().repo, HEAD), shard);
    let err = now(env.pipe.update_ref(&a, upd(HEAD, Missing, A))).unwrap_err();
    assert!(injected.load(Ordering::SeqCst));
    assert_eq!(err.code(), Code::Aborted);
    assert_eq!(
        now(env.pipe.meta.inner.get(&shard, &keys::quota_shard(window))).unwrap(),
        Some(codec::encode_namespace_usage(
            crate::quota::NamespaceUsage { ops: 2, bytes: 0 }
        ))
    );
    assert!(
        now(env.pipe.meta.inner.get(&shard, &keys::replay(&[3; 32])))
            .unwrap()
            .is_none()
    );
}

// --------------------------------------------------------- advance refs

#[test]
fn advance_refs_atomic_store_conflict_leaves_both_untouched() {
    for auth in [AuthMode::Open, authv2()] {
        let env = env(auth);
        assert!(env.pipe.capabilities().atomic_advance);
        seed(env.pipe.meta.inner.as_ref(), &[(HEAD, A), (PACKMAP, A)]);
        let req = |n| {
            let r = Req::signed(
                &key(7),
                Procedure::AdvanceRefs,
                &nonce(n).into_bytes(),
                &nonce(n),
                T0,
            );
            if matches!(env.pipe.cfg.auth, AuthMode::Open) {
                Req::unsigned(Procedure::AdvanceRefs)
            } else {
                r
            }
        };
        let cases = [
            (
                upd(HEAD, Match(A), B),
                upd(PACKMAP, Match(C), B),
                AdvanceOutcome::PackmapConflict,
            ),
            (
                upd(HEAD, Match(C), B),
                upd(PACKMAP, Match(A), B),
                AdvanceOutcome::HeadConflict,
            ),
            // Both conflict: the packmap takes precedence.
            (
                upd(HEAD, Missing, B),
                upd(PACKMAP, Missing, B),
                AdvanceOutcome::PackmapConflict,
            ),
        ];
        for (n, (head, pm, outcome)) in (1..).zip(cases) {
            assert_eq!(env.advance(&req(n), &head, &pm).unwrap(), outcome);
            assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(A)));
        }
        let (head, pm) = (upd(HEAD, Match(A), B), upd(PACKMAP, Match(A), C));
        assert_eq!(
            env.advance(&req(9), &head, &pm).unwrap(),
            AdvanceOutcome::Committed
        );
        assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(B), Some(C)));
    }
}

#[test]
fn advance_refs_nonatomic_store_matches_trait_default_order() {
    let clock = clock();
    let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
    let env = build(cfg(AuthMode::Open), Spy::new(kv), Hooks::new(), clock);
    assert!(!env.pipe.capabilities().atomic_advance);
    seed(env.pipe.meta.inner.as_ref(), &[(HEAD, A), (PACKMAP, A)]);
    let req = Req::unsigned(Procedure::AdvanceRefs);
    // Head conflict: the packmap is already written (protocol.rs order).
    let (head, pm) = (upd(HEAD, Match(C), B), upd(PACKMAP, Match(A), B));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::HeadConflict
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(B)));
    // Packmap conflict: the head is never attempted.
    let (head, pm) = (upd(HEAD, Match(A), C), upd(PACKMAP, Match(A), C));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::PackmapConflict
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(B)));
    let (head, pm) = (upd(HEAD, Match(A), C), upd(PACKMAP, Match(B), C));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(C), Some(C)));
    // Two sequential single-key batches, each with its own deadline.
    let last: Vec<_> = env.batches().into_iter().rev().take(2).collect();
    for batch in last {
        assert!(matches!(batch.preconditions[0], Precondition::NotAfter(_)));
        assert_eq!(batch.writes.len(), 1);
    }
}

// ---------------------------------------------------------- other modes

#[test]
fn bearer_mode_rejects_missing_or_wrong_token_on_reads_and_writes() {
    let env = env(AuthMode::Bearer {
        token: crate::error::Redacted::new("s3cr3t"),
    });
    let all = [
        Procedure::ListRefs,
        Procedure::ReadRef,
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::PackExists,
        Procedure::UploadPack,
        Procedure::DownloadPack,
    ];
    for procedure in all {
        let bare = Req::unsigned(procedure);
        for req in [
            bare.clone(),
            bare.clone().header("authorization", "Bearer wrong!"),
            bare.clone().header("authorization", "s3cr3t"),
            bare.clone().header("authorization", "Bearer s3cr3tt"),
        ] {
            let err = env.auth(&req).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated);
            assert!(!format!("{err} {err:?}").contains("s3cr3t"));
        }
        let ok = env
            .auth(&bare.header("authorization", "Bearer s3cr3t"))
            .unwrap();
        assert_eq!(ok.principal, Principal::BearerHolder);
    }
    let req = Req::unsigned(Procedure::UpdateRef).header("authorization", "Bearer s3cr3t");
    env.update(&req, &upd(HEAD, Missing, A)).unwrap();
    assert_eq!(env.count("p") + env.count("q"), 0, "no replay or quota");
}

#[test]
fn open_mode_allows_everything_without_replay() {
    let env = env(AuthMode::Open);
    assert_eq!(
        env.open_update(&upd(HEAD, Missing, A)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.open_update(&upd(HEAD, Missing, B)).unwrap(),
        UpdateRefResult::Conflict { current: Some(A) }
    );
    let req = Req::unsigned(Procedure::AdvanceRefs);
    let (head, pm) = (upd(HEAD, Match(A), B), upd(PACKMAP, Missing, B));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.read(HEAD), Some(B));
    for tag in ["p", "px", "q", "qx"] {
        assert_eq!(env.count(tag), 0, "{tag}");
    }
    // An unsigned conflict needs no write at all.
    let writes = env.batches().len();
    env.open_update(&upd(HEAD, Match(C), A)).unwrap();
    assert_eq!(env.batches().len(), writes);
}

#[test]
fn transport_identity_mode_uses_binding_principal() {
    let env = env(AuthMode::TransportIdentity);
    let ssh = Principal::SshForcedCommand { key: None };
    let mut req = Req::unsigned(Procedure::UpdateRef);
    assert_eq!(code(env.auth(&req)), Code::Unauthenticated);
    req.principal = Some(ssh.clone());
    let a = env.auth(&req).unwrap();
    assert_eq!((a.principal, a.auth), (ssh, None));
    env.update(&req, &upd(HEAD, Missing, A)).unwrap();
    assert_eq!(env.count("p"), 0);
}

struct Fixed(AdmissionDecision);

impl Admission for Fixed {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Ok(self.0.clone())
    }
}

#[test]
fn admission_challenge_maps_to_permission_denied_and_writes_nothing() {
    let challenge = AdmissionDecision::Challenge {
        challenges: vec![Challenge {
            scheme: "mpp".into(),
            value: "id=1".into(),
        }],
        description: "pay".into(),
        response_headers: Vec::new(),
    };
    let denied = AdmissionDecision::Deny(ServerError::permission_denied("no"));
    for (decision, message, status) in [(challenge, "admission required", 402), (denied, "no", 403)]
    {
        let clock = clock();
        let hooks = with_admission(Fixed(decision));
        let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
        let u = upd(HEAD, Missing, A);
        let req = Req::update(&key(7), 1, &u, T0);
        let err = env.update(&req, &u).unwrap_err();
        assert_eq!(
            (err.code(), err.public_message()),
            (Code::PermissionDenied, message)
        );
        assert_eq!(err.http_status(), Some(status));
        assert_eq!(err.details().is_empty(), status != 402);
        if status == 402 {
            assert!(
                err.headers()
                    .iter()
                    .any(|(name, value)| name == "Cache-Control" && value == "no-store")
            );
        }
        assert!(env.batches().is_empty() && env.rows().is_empty());
    }
}

struct NumberedReservation(AtomicU32);
impl Admission for NumberedReservation {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let number = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(AdmissionDecision::allow(Vec::new()).with_reservation(format!("reserved-{number}")))
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Exercises the full backlog transition and recovery in one fixture.
fn reserved_commit_conflict_backpressure_and_recovery() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.outbox_backlog_cap = Some(OutboxBacklogCap {
        rows: 1,
        bytes: u64::MAX,
    });
    let env = build(
        config,
        Spy::new(store(&clock)),
        with_admission(NumberedReservation(AtomicU32::new(0))),
        clock.clone(),
    );
    let k = key(7);
    let first = upd(HEAD, Missing, A);
    assert_eq!(
        env.update(&Req::update(&k, 1, &first, T0), &first).unwrap(),
        UpdateRefResult::Committed
    );
    let first_row = now(env
        .pipe
        .meta
        .get(&ns(), &keys::reservation("reserved-0").unwrap()))
    .unwrap()
    .unwrap();
    assert!(matches!(
        codec::decode_reservation(&first_row).unwrap(),
        codec::ReservationV1::Committed { .. }
    ));
    assert!(env.batches().iter().any(|batch| batch.writes.iter().any(|write| matches!(write, Write::Put(key, _) if *key == keys::timer((T0 as u64) + 41_000, 9, b"reserved-0")))));
    let guarded = env.batches().into_iter().find(|batch| batch.preconditions.iter().any(|pre| matches!(pre, Precondition::Equals(key, _) if *key == keys::reservation("reserved-0").unwrap()))).unwrap();
    assert!(guarded.preconditions.iter().any(
        |pre| matches!(pre, Precondition::NotAfter(deadline) if *deadline <= T0 as u64 + 10_000)
    ));

    let conflict = upd(HEAD, Missing, B);
    assert_eq!(
        env.update(&Req::update(&k, 2, &conflict, T0), &conflict)
            .unwrap(),
        UpdateRefResult::Conflict { current: Some(A) }
    );
    let second_row = now(env
        .pipe
        .meta
        .get(&ns(), &keys::reservation("reserved-1").unwrap()))
    .unwrap()
    .unwrap();
    assert!(matches!(
        codec::decode_reservation(&second_row).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::RefConflict,
            ..
        }
    ));
    assert_eq!(
        codec::decode_backlog(
            &now(env.pipe.meta.get(&ns(), &keys::outcome_backlog()))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .rows,
        2
    );

    let third = upd(HEAD, Any, B);
    let before = env.pipe.hooks.admission.0.load(Ordering::SeqCst);
    let err = env
        .update(&Req::update(&k, 3, &third, T0), &third)
        .unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unavailable, "outbox backlog; retry")
    );
    assert!(
        err.headers()
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "30")
    );
    assert_eq!(env.pipe.hooks.admission.0.load(Ordering::SeqCst), before);
    assert_eq!(env.metrics.count("mkit_server_outbox_backpressure"), 1);
    assert_eq!(env.read(HEAD), Some(A));

    let registry = crate::timers::TimerRegistry::new().register(
        crate::timers::outcome_delivery::OutcomeDelivery::new(
            NoOutcomes,
            AUDIENCE.into(),
            Arc::new(crate::NoopMetrics),
            Arc::new(crate::rt::ManualSleep::new()),
        ),
    );
    let report = now(crate::timers::run_due(
        &env.pipe.meta,
        &ns(),
        &registry,
        clock.as_ref(),
        T0 as u64,
        &crate::timers::TickBudget::default(),
    ))
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(
        now(env.pipe.meta.get(&ns(), &keys::outcome_backlog()))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        env.update(&Req::update(&k, 3, &third, T0), &third).unwrap(),
        UpdateRefResult::Committed
    );
}

#[test]
fn pending_guard_loss_commits_no_ref_and_does_not_replan() {
    let clock = clock();
    let raced = Arc::new(AtomicBool::new(false));
    let once = raced.clone();
    let store = Spy::new(store(&clock)).hook(move |inner, partition, batch| {
        let key = keys::reservation("race-reservation").unwrap();
        let prior = batch.preconditions.iter().find_map(|pre| match pre {
            Precondition::Equals(found, value) if *found == key => Some(value.clone()),
            _ => None,
        });
        if let Some(prior) = prior
            && !once.swap(true, Ordering::SeqCst)
        {
            let mut outbox = crate::store::outbox::OutboxBuilder::new(None, None).unwrap();
            outbox.outcome(
                "race-reservation",
                &prior,
                crate::store::outbox::Terminal::new(codec::ReservationV1::Aborted {
                    repository: REPO.into(),
                    occurred_at_ms: T0 as u64 + 41_000,
                    reason: codec::AbortReason::Abandoned,
                    detail: String::new(),
                })
                .unwrap(),
            );
            let mut replacement = Batch::new();
            outbox
                .try_finish(&mut replacement.preconditions, &mut replacement.writes)
                .unwrap();
            assert_eq!(
                now(inner.apply(partition, replacement)).unwrap(),
                BatchOutcome::Committed
            );
        }
    });
    let env = build(
        cfg(authv2()),
        store,
        with_admission(Fixed(
            AdmissionDecision::allow(Vec::new()).with_reservation("race-reservation"),
        )),
        clock,
    );
    let update = upd(HEAD, Missing, A);
    let err = env
        .update(&Req::update(&key(7), 1, &update, T0), &update)
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(env.read(HEAD), None);
    assert!(raced.load(Ordering::SeqCst));
    let row = now(env
        .pipe
        .meta
        .get(&ns(), &keys::reservation("race-reservation").unwrap()))
    .unwrap()
    .unwrap();
    assert!(matches!(
        codec::decode_reservation(&row).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::Abandoned,
            ..
        }
    ));
    assert_eq!(env.count("oq"), 1);
    assert_eq!(env.batches().iter().filter(|batch| batch.writes.iter().any(|write| matches!(write, Write::Put(found, _) if *found == keys::ref_key(&repo_name(), HEAD)))).count(), 1);
}

#[test]
fn invalid_admission_decisions_leave_no_metadata() {
    let one = Challenge {
        scheme: "mpp".into(),
        value: "token".into(),
    };
    let decisions = [
        AdmissionDecision::challenge(Vec::new(), ""),
        AdmissionDecision::challenge(vec![one.clone(); 9], ""),
        AdmissionDecision::challenge(
            vec![Challenge {
                scheme: "MPP".into(),
                ..one.clone()
            }],
            "",
        ),
        AdmissionDecision::challenge(
            vec![Challenge {
                value: "x".repeat(8_193),
                ..one.clone()
            }],
            "",
        ),
        AdmissionDecision::challenge(vec![one.clone()], "x".repeat(513)),
        AdmissionDecision::challenge(
            vec![Challenge {
                value: "bad\n".into(),
                ..one.clone()
            }],
            "",
        ),
        AdmissionDecision::challenge(vec![one.clone()], "").with_response_header("Set-Cookie", "x"),
        AdmissionDecision::challenge(vec![one], "")
            .with_response_header("PAYMENT-REQUIRED", "bad\t"),
        AdmissionDecision::allow(Vec::new()).with_response_header("WWW-Authenticate", "x"),
        AdmissionDecision::allow(Vec::new()).with_response_header("Payment-Receipt", "bad\n"),
        AdmissionDecision::allow(Vec::new()).with_reservation("s:client"),
        AdmissionDecision::allow(Vec::new()).with_reservation("bad/id"),
        AdmissionDecision::allow(Vec::new()).with_external_ref("bad space"),
        AdmissionDecision::allow(Vec::new()).with_external_ref("x".repeat(257)),
    ];
    for decision in decisions {
        let clock = clock();
        let env = build(
            cfg(authv2()),
            Spy::new(store(&clock)),
            with_admission(Fixed(decision)),
            clock,
        );
        let update = upd(HEAD, Missing, A);
        let err = env
            .update(&Req::update(&key(7), 1, &update, T0), &update)
            .unwrap_err();
        assert_eq!(
            (err.code(), err.public_message()),
            (Code::Unavailable, "admission unavailable")
        );
        assert!(env.batches().is_empty() && env.rows().is_empty());
    }
}

#[test]
fn admission_denial_sanitizes_long_and_control_messages() {
    for message in ["x".repeat(513), "bad\nline".into()] {
        let clock = clock();
        let env = build(
            cfg(authv2()),
            Spy::new(store(&clock)),
            with_admission(Fixed(AdmissionDecision::Deny(
                ServerError::permission_denied(message),
            ))),
            clock,
        );
        let update = upd(HEAD, Missing, A);
        let err = env
            .update(&Req::update(&key(7), 1, &update, T0), &update)
            .unwrap_err();
        assert_eq!(
            (err.code(), err.http_status(), err.public_message()),
            (Code::PermissionDenied, Some(403), "admission denied")
        );
        assert!(err.details().is_empty() && err.headers().is_empty());
        assert!(env.batches().is_empty());
    }
}

struct SmugglingAuthorizer;
impl Authorizer for SmugglingAuthorizer {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Err(ServerError::admission_challenge(bytes::Bytes::from_static(
            b"secret",
        )))
    }
}
struct SmugglingAdmission;
impl Admission for SmugglingAdmission {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Err(ServerError::admission_challenge(bytes::Bytes::from_static(
            b"secret",
        )))
    }
}
struct SmugglingPreReceive;
impl PreReceive for SmugglingPreReceive {
    async fn check(
        &self,
        _: &Operation,
        _: Option<&crate::store::BlobKey>,
    ) -> Result<(), ServerError> {
        Err(ServerError::admission_challenge(bytes::Bytes::from_static(
            b"secret",
        )))
    }
}

#[test]
fn only_stage_three_can_issue_a_challenge() {
    let update = upd(HEAD, Missing, A);
    let request = Req::update(&key(7), 1, &update, T0);
    let authorizer_clock = clock();
    let authorizer = build(
        cfg(authv2()),
        Spy::new(store(&authorizer_clock)),
        Hooks {
            authorizer: SmugglingAuthorizer,
            admission: DefaultAdmission,
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        authorizer_clock,
    );
    let admission_clock = clock();
    let admission = build(
        cfg(authv2()),
        Spy::new(store(&admission_clock)),
        with_admission(SmugglingAdmission),
        admission_clock,
    );
    let pre_receive_clock = clock();
    let pre_receive = build(
        cfg(authv2()),
        Spy::new(store(&pre_receive_clock)),
        Hooks {
            authorizer: OpenAuthorizer,
            admission: DefaultAdmission,
            pre_receive: SmugglingPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        pre_receive_clock,
    );
    for err in [
        authorizer.update(&request, &update).unwrap_err(),
        admission.update(&request, &update).unwrap_err(),
        pre_receive.update(&request, &update).unwrap_err(),
    ] {
        assert_eq!(
            (err.code(), err.http_status()),
            (Code::PermissionDenied, Some(403))
        );
        assert!(err.details().is_empty() && err.headers().is_empty());
    }
}

fn assert_one_abort<H: HookSet>(env: &Env<H>, rid: &str, reason: codec::AbortReason) {
    let row = now(env.pipe.meta.get(&ns(), &keys::reservation(rid).unwrap()))
        .unwrap()
        .unwrap();
    assert!(
        matches!(codec::decode_reservation(&row).unwrap(), codec::ReservationV1::Aborted { reason: actual, .. } if actual == reason)
    );
    assert_eq!(env.count("oq"), 1);
    assert_eq!(
        codec::decode_backlog(
            &now(env.pipe.meta.get(&ns(), &keys::outcome_backlog()))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .rows,
        1
    );
}

struct RejectPreReceive;
impl PreReceive for RejectPreReceive {
    async fn check(
        &self,
        _: &Operation,
        _: Option<&crate::store::BlobKey>,
    ) -> Result<(), ServerError> {
        Err(ServerError::permission_denied("pre receive refused"))
    }
}

struct ReservedDefault;
impl Admission for ReservedDefault {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Ok(DefaultAdmission
            .admit(input)
            .await?
            .with_reservation("quota-rid"))
    }
}

#[test]
fn reserved_pre_receive_and_quota_exits_each_write_one_abort() {
    let update = upd(HEAD, Missing, A);
    let request = Req::update(&key(7), 1, &update, T0);
    let pre_clock = clock();
    let pre = build(
        cfg(authv2()),
        Spy::new(store(&pre_clock)),
        Hooks {
            authorizer: OpenAuthorizer,
            admission: Fixed(AdmissionDecision::allow(Vec::new()).with_reservation("pre-rid")),
            pre_receive: RejectPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        pre_clock,
    );
    assert_eq!(
        pre.update(&request, &update).unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_one_abort(&pre, "pre-rid", codec::AbortReason::Unspecified);

    let quota_clock = clock();
    let mut config = cfg(authv2());
    config.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 0,
        max_bytes: u64::MAX,
    });
    let quota = build(
        config,
        Spy::new(store(&quota_clock)),
        with_admission(ReservedDefault),
        quota_clock,
    );
    assert_eq!(
        quota.update(&request, &update).unwrap_err().code(),
        Code::ResourceExhausted
    );
    assert_one_abort(&quota, "quota-rid", codec::AbortReason::Unspecified);
}

#[test]
fn reserved_store_error_and_deadline_each_write_one_abort() {
    for store_error in [false, true] {
        let current = clock();
        let mut spy = Spy::new(store(&current));
        let fail = spy.fail_next_apply.clone();
        let moved = current.clone();
        spy.after_hook = Some(Box::new(move |_, _, batch, result| {
            if !matches!(result, BatchOutcome::Committed) {
                return;
            }
            let pending = batch.writes.iter().any(|write| matches!(write,
                Write::Put(_, value) if matches!(codec::decode_reservation(value), Ok(codec::ReservationV1::Pending { .. }))));
            if pending {
                if store_error {
                    fail.store(true, Ordering::SeqCst);
                } else {
                    moved.set(T0 + 11_000);
                }
            }
        }));
        let rid = if store_error {
            "store-rid"
        } else {
            "deadline-rid"
        };
        let env = build(
            cfg(authv2()),
            spy,
            with_admission(Fixed(
                AdmissionDecision::allow(Vec::new()).with_reservation(rid),
            )),
            current,
        );
        let update = upd(HEAD, Missing, A);
        let err = env
            .update(&Req::update(&key(7), 1, &update, T0), &update)
            .unwrap_err();
        assert_eq!(
            err.code(),
            if store_error {
                Code::Internal
            } else {
                Code::Unavailable
            }
        );
        assert_one_abort(&env, rid, codec::AbortReason::Internal);
        assert_eq!(env.read(HEAD), None);
    }
}

struct GrantEpochZero;
impl Authorizer for GrantEpochZero {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts {
            authority_generation: None,
            grant: Some(crate::op::GrantRef {
                id: [9; 32],
                epoch: 0,
                presence_requirement: None,
            }),
            ..AuthzFacts::default()
        })
    }
}

#[test]
fn reserved_grant_epoch_loss_writes_one_abort() {
    let current = clock();
    let mut spy = Spy::new(store(&current));
    spy.after_hook = Some(Box::new(move |inner, partition, batch, result| {
        if !matches!(result, BatchOutcome::Committed) {
            return;
        }
        if batch.writes.iter().any(|write| {
            matches!(write, Write::Put(_, value)
            if matches!(codec::decode_reservation(value), Ok(codec::ReservationV1::Pending { .. })))
        }) {
            assert_eq!(
                now(inner.apply(
                    partition,
                    Batch::new().put(keys::grant_epoch(), codec::encode_u64(1))
                ))
                .unwrap(),
                BatchOutcome::Committed
            );
        }
    }));
    let env = build(
        cfg(authv2()),
        spy,
        Hooks {
            authorizer: GrantEpochZero,
            admission: Fixed(AdmissionDecision::allow(Vec::new()).with_reservation("epoch-rid")),
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        current,
    );
    let update = upd(HEAD, Missing, A);
    let err = env
        .update(&Req::update(&key(7), 1, &update, T0), &update)
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_one_abort(&env, "epoch-rid", codec::AbortReason::EpochMismatch);
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn reservation_abort_reasons_follow_the_source_of_the_error() {
    use codec::AbortReason;
    use reservation::abort_reason;

    assert_eq!(
        abort_reason(
            &ServerError::aborted_retryable("write contention; retry")
                .with_abort_cause(AbortCause::Contention)
        )
        .0,
        AbortReason::Internal
    );
    assert_eq!(
        abort_reason(&ServerError::aborted_retryable(
            "operation already in flight; retry"
        ))
        .0,
        AbortReason::ReplayRace
    );
    assert_eq!(
        abort_reason(&ServerError::permission_denied(
            "pre-receive rejected epoch label"
        ))
        .0,
        AbortReason::Unspecified
    );
    assert_eq!(
        abort_reason(
            &ServerError::aborted_retryable("namespace quota window advanced; retry")
                .with_abort_cause(AbortCause::QuotaWindow)
        )
        .0,
        AbortReason::Unspecified
    );
}

#[test]
fn pipeline_new_rejects_authv2_over_refs_only_store() {
    let clock = clock();
    let blobs = MemoryBlobStore::default();
    let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
    let metrics: Arc<dyn Metrics> = Arc::new(crate::NoopMetrics);
    let err = Pipeline::new(blobs, kv, Hooks::new(), cfg(authv2()), clock, metrics).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn refs_only_store_never_sees_layout_version_key() {
    for auth in [AuthMode::Open, AuthMode::TransportIdentity] {
        let clock = clock();
        let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
        let env = build(cfg(auth), Spy::new(kv), Hooks::new(), clock);
        let principal = Some(Principal::SshForcedCommand { key: None });
        let req = |p| Req {
            principal: principal.clone(),
            ..Req::unsigned(p)
        };
        env.update(&req(Procedure::UpdateRef), &upd(HEAD, Missing, A))
            .unwrap();
        let (head, pm) = (upd(HEAD, Any, B), upd(PACKMAP, Missing, B));
        env.advance(&req(Procedure::AdvanceRefs), &head, &pm)
            .unwrap();
        let a = env.auth(&req(Procedure::ListRefs)).unwrap();
        assert_eq!(block_on(env.pipe.list_refs(&a, "")).unwrap().len(), 2);
        let seen = env.pipe.meta.seen.lock().unwrap().clone();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(keys::is_ref_key), "{seen:?}");
    }
}

// ------------------------------------------------------ pure planners

fn repo_name() -> RepoName {
    RepoName::new(REPO).unwrap()
}

fn clock_at(plan_time_ms: u64, deadline_cap: Option<u64>) -> PlanClock {
    PlanClock {
        plan_time_ms,
        business_now_ms: i64::try_from(plan_time_ms).unwrap(),
        max_apply_window_ms: WINDOW,
        deadline_cap,
    }
}

fn snapshot(req: &WriteRequest<'_>, values: &[(Key, Value)]) -> Snapshot {
    let mut snap = Snapshot::default();
    for key in req.read_keys() {
        let value = values
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone());
        snap.insert(key, value);
    }
    snap
}

fn simple_index_batch(
    repo: &RepoId,
    source: &Partition,
    shards: &dyn ShardMap,
    refs: &[RefUpdate],
    values: &[(Key, Value)],
    index: bool,
) -> Planned {
    let req = WriteRequest {
        authority_generation: None,
        repo: &repo.name,
        kind: if refs.len() == 1 {
            WriteKind::UpdateRef
        } else {
            WriteKind::AdvanceRefs
        },
        refs,
        ref_index: index.then_some((repo, source, shards)),
        replay: None,
        charges: &[],
        namespace_charge: None,
        grant: None,
        lease: None,
        layout_version: false,
        mark_repo_known: false,
        begin: None,
        advance: None,
        implicit: None,
        rejection: None,
        pending: None,
    };
    plan_write(&req, &snapshot(&req, values), &clock_at(5, None)).unwrap()
}

fn index_relays(batch: &Batch) -> Vec<codec::RelayV1> {
    batch
        .writes
        .iter()
        .filter_map(|write| match write {
            Write::Put(key, value)
                if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))) =>
            {
                Some(codec::decode_relay(value).unwrap())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn planner_relays_every_d34_ref_form_and_no_conflict_or_single() {
    let repo = repo();
    let shards = D34Shards;
    let head = upd(HEAD, Missing, A);
    let source = shards.ref_shard(&repo, HEAD);
    let Planned::Apply(update) = simple_index_batch(
        &repo,
        &source,
        &shards,
        std::slice::from_ref(&head),
        &[],
        true,
    ) else {
        panic!("update")
    };
    let rows = index_relays(&update.batch);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target, shards.ref_index(&repo, HEAD));
    assert_eq!(
        rows[0].puts,
        vec![(
            keys::ref_index_key(&repo.name, HEAD),
            codec::encode_ref_id(&A)
        )]
    );
    assert_eq!(
        update
            .batch
            .preconditions
            .iter()
            .filter(
                |pre| matches!(pre, Precondition::Absent(key) if *key == keys::outbox_sequence())
            )
            .count(),
        1
    );
    assert_eq!(update.batch.writes.iter().filter(|write| matches!(write, Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind: 3, .. })))).count(), 1);

    let pair = [upd(PACKMAP, Missing, B), head.clone()];
    let Planned::Apply(different) = simple_index_batch(&repo, &source, &shards, &pair, &[], true)
    else {
        panic!("advance")
    };
    assert_ne!(
        shards.ref_index(&repo, HEAD),
        shards.ref_index(&repo, PACKMAP)
    );
    assert_eq!(index_relays(&different.batch).len(), 2);
    let same_branch = (0..1000)
        .find_map(|i| {
            let name = format!("refs/heads/b{i}");
            let pm = format!("refs/mkit/packmap/b{i}");
            (shards.ref_index(&repo, &name) == shards.ref_index(&repo, &pm)).then_some((name, pm))
        })
        .unwrap();
    let same_source = shards.ref_shard(&repo, &same_branch.0);
    let same_pair = [
        upd(&same_branch.1, Missing, B),
        upd(&same_branch.0, Missing, A),
    ];
    let Planned::Apply(same) =
        simple_index_batch(&repo, &same_source, &shards, &same_pair, &[], true)
    else {
        panic!("same bucket")
    };
    assert_eq!(index_relays(&same.batch).len(), 1);
    assert_eq!(index_relays(&same.batch)[0].puts.len(), 2);

    let deletion = RefUpdate {
        new: None,
        condition: Match(A),
        ..head.clone()
    };
    let prior = [ref_value(HEAD, A)];
    let Planned::Apply(deleted) =
        simple_index_batch(&repo, &source, &shards, &[deletion], &prior, true)
    else {
        panic!("delete")
    };
    assert_eq!(
        index_relays(&deleted.batch)[0].deletes,
        vec![keys::ref_index_key(&repo.name, HEAD)]
    );
    assert!(matches!(
        simple_index_batch(
            &repo,
            &source,
            &shards,
            std::slice::from_ref(&head),
            &prior,
            true,
        ),
        Planned::Done(_)
    ));
    let Planned::Apply(single) = simple_index_batch(&repo, &source, &shards, &[head], &[], false)
    else {
        panic!("single")
    };
    assert!(index_relays(&single.batch).is_empty());
}

fn ref_value(name: &str, id: Hash) -> (Key, Value) {
    (keys::ref_key(&repo_name(), name), codec::encode_ref_id(&id))
}

#[test]
fn plan_cas_any_missing_match_on_snapshot() {
    let name = repo_name();
    let cases = [
        (Any, None, true),
        (Any, Some(A), true),
        (Missing, None, true),
        (Missing, Some(A), false),
        (Match(A), Some(A), true),
        (Match(A), Some(B), false),
        (Match(A), None, false),
    ];
    for (condition, current, commits) in cases {
        let refs = [upd(HEAD, condition, C)];
        let req = WriteRequest {
            authority_generation: None,
            repo: &name,
            kind: WriteKind::UpdateRef,
            refs: &refs,
            ref_index: None,
            replay: None,
            charges: &[],
            namespace_charge: None,
            grant: None,
            layout_version: false,
            mark_repo_known: false,
            lease: None,
            rejection: None,
            pending: None,
            begin: None,
            advance: None,
            implicit: None,
        };
        let values: Vec<_> = current.map(|id| ref_value(HEAD, id)).into_iter().collect();
        let planned = plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap();
        match planned {
            Planned::Apply(plan) => {
                assert!(commits, "{condition:?} {current:?}");
                assert_eq!(
                    plan.on_commit,
                    StoredResult::UpdateRef(UpdateRefResult::Committed)
                );
                assert_eq!(
                    plan.batch.writes,
                    vec![Write::Put(ref_value(HEAD, C).0, ref_value(HEAD, C).1)]
                );
                let guarded = plan.batch.preconditions.len() == 2;
                assert_eq!(guarded, condition != Any, "Any is never guarded");
            }
            Planned::Done(result) => {
                assert!(!commits, "{condition:?} {current:?}");
                assert_eq!(
                    result,
                    StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                );
            }
        }
    }
}

fn replay() -> ReplayGuard {
    ReplayGuard {
        scope: [1; 32],
        fingerprint: [2; 32],
        expires_at_ms: T0,
    }
}

#[test]
fn plan_conflict_writes_only_the_replay_record() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Match(A), C), upd(HEAD, Match(A), C)];
    let req = WriteRequest {
        authority_generation: None,
        repo: &name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        ref_index: None,
        replay: Some(replay()),
        charges: &[],
        namespace_charge: None,
        grant: None,
        layout_version: false,
        mark_repo_known: false,
        lease: None,
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let values = [ref_value(PACKMAP, A), ref_value(HEAD, B)];
    let Planned::Apply(plan) =
        plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap()
    else {
        panic!("a signed conflict is stored");
    };
    assert_eq!(
        plan.on_commit,
        StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict)
    );
    let written: Vec<_> = plan
        .batch
        .writes
        .iter()
        .map(|w| match w {
            Write::Put(k, _) | Write::Delete(k) => keys::parse(k),
        })
        .collect();
    assert!(matches!(
        written[..],
        [
            Some(keys::ParsedKey::Replay(_)),
            Some(keys::ParsedKey::ReplayExpiry { .. })
        ]
    ));
    // Both refs that decided the conflict are guarded with what was read.
    assert_eq!(
        plan.batch.preconditions[1..],
        [
            Precondition::Equals(values[0].0.clone(), values[0].1.clone()),
            Precondition::Equals(values[1].0.clone(), values[1].1.clone()),
            Precondition::Absent(keys::replay(&[1; 32])),
        ]
    );
    assert_eq!(plan.replay_index, Some(3));
}

fn charge(max_ops: u32) -> QuotaCharge {
    QuotaCharge {
        scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[3; 32]),
        bytes: 0,
        limits: QuotaLimits {
            window_ms: 60_000,
            max_ops,
            max_bytes: 0,
        },
    }
}

#[test]
fn plan_quota_exhaustion_yields_no_batch() {
    let name = repo_name();
    let refs = [upd(HEAD, Any, C)];
    let charges = [charge(1)];
    let req = WriteRequest {
        authority_generation: None,
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        ref_index: None,
        replay: Some(replay()),
        charges: &charges,
        namespace_charge: None,
        grant: None,
        layout_version: true,
        mark_repo_known: false,
        lease: None,
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let used = QuotaState {
        window_start: T0,
        ops: 1,
        bytes: 0,
    };
    let values = [(
        keys::quota(&charges[0].scope),
        codec::encode_quota_state(&used),
    )];
    let err = plan_write(&req, &snapshot(&req, &values), &clock_at(ms(T0) + 1, None)).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
}

fn condition() -> impl Strategy<Value = RefWriteCondition> {
    prop_oneof![Just(Any), Just(Missing), Just(Match(A)), Just(Match(B))]
}

fn maybe_id() -> impl Strategy<Value = Option<Hash>> {
    prop_oneof![Just(None), Just(Some(A)), Just(Some(B))]
}

proptest! {
    #[test]
    fn plan_guards_every_read_and_starts_with_not_after(
        advance in any::<bool>(),
        conditions in (condition(), condition()),
        currents in (maybe_id(), maybe_id()),
        signed in any::<bool>(),
        quota in prop::option::of(0u32..3),
        layout in prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
        plan_time in 0u64..1_000_000,
        cap in prop::option::of(0u64..1_100_000),
    ) {
        let name = repo_name();
        let refs = [upd(PACKMAP, conditions.0, C), upd(HEAD, conditions.1, C)];
        let refs = if advance { &refs[..] } else { &refs[1..] };
        let charges: Vec<_> = quota.map(|_| charge(2)).into_iter().collect();
        let req = WriteRequest {
            authority_generation: None,
            repo: &name,
            kind: if advance { WriteKind::AdvanceRefs } else { WriteKind::UpdateRef },
            refs,
            ref_index: None,
            replay: signed.then(replay),
            charges: &charges,
            namespace_charge: None,
            grant: None,
            layout_version: layout.is_some(),
            mark_repo_known: false,
                    lease: None,
            rejection: None,
            pending: None,
                    begin: None,
            advance: None,
            implicit: None,
        };
        let mut values = Vec::new();
        for (name, current) in [(PACKMAP, currents.0), (HEAD, currents.1)] {
            values.extend(current.map(|id| ref_value(name, id)));
        }
        if let Some(ops) = quota.filter(|ops| *ops > 0) {
            let state = QuotaState { window_start: 0, ops, bytes: 0 };
            values.push((keys::quota(&charges[0].scope), codec::encode_quota_state(&state)));
        }
        if layout == Some(true) {
            values.push((keys::layout_version(), codec::encode_u32(LAYOUT_VERSION)));
        }
        let snap = snapshot(&req, &values);
        let clock = clock_at(plan_time, cap);
        let planned = plan_write(&req, &snap, &clock);
        let plan = match planned {
            Err(e) => { prop_assert_eq!(e.code(), Code::ResourceExhausted); return Ok(()); }
            Ok(Planned::Done(_)) => { prop_assert!(!signed && charges.is_empty()); return Ok(()); }
            Ok(Planned::Apply(plan)) => plan,
        };
        let expected = cap.map_or(plan_time + WINDOW, |c| c.min(plan_time + WINDOW));
        prop_assert_eq!(&plan.batch.preconditions[0], &Precondition::NotAfter(expected));
        prop_assert_eq!(plan.batch.preconditions.iter().filter(|p| matches!(p, Precondition::NotAfter(_))).count(), 1);
        let replay_key = keys::replay(&[1; 32]);
        for pre in &plan.batch.preconditions[1..] {
            match pre {
                Precondition::Equals(k, v) => prop_assert_eq!(snap.get(k), Some(v)),
                Precondition::Absent(k) if *k == replay_key => {}
                Precondition::Absent(k) => prop_assert_eq!(snap.get(k), None),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
        }
        let guarded = |k: &Key| plan.batch.preconditions.iter().any(|p| matches!(p,
            Precondition::Equals(g, _) | Precondition::Absent(g) if g == k));
        for k in req.read_keys().iter().filter(|k| !keys::is_ref_key(k)) {
            prop_assert!(guarded(k), "{:?} unguarded", k);
        }
        for update in refs.iter().filter(|u| u.condition != Any) {
            let k = keys::ref_key(&name, &update.name);
            let decided = plan.batch.writes.iter().any(|w| matches!(w, Write::Put(p, _) if *p == k));
            prop_assert!(!decided || guarded(&k), "{} written unguarded", update.name);
        }
        prop_assert!(plan.batch.validate(&StoreCapabilities::full()).is_ok());
    }
}

fn verified(expires_at: i64) -> VerifiedAuth {
    let authorized = mkit_core::write_auth::Authorized {
        scope: "11".repeat(32),
        public_key: "22".repeat(32),
        nonce: "ab".repeat(32),
        fingerprint: "33".repeat(32),
        commitment: format!("body:{}", "cd".repeat(32)),
        expires_at,
    };
    VerifiedAuth::try_from(&authorized).unwrap()
}

fn charges_for(input: &AdmissionInput<'_>) -> Vec<QuotaCharge> {
    match block_on(DefaultAdmission.admit(input)).unwrap() {
        AdmissionDecision::Allow { charges, .. } => charges,
        other => panic!("{other:?}"),
    }
}

#[test]
fn default_admission_charges_signed_writes_only() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let auth = verified(T0);
    let op = |kind, auth: Option<VerifiedAuth>| {
        let principal = auth
            .as_ref()
            .map_or(Principal::Anonymous, |a| Principal::Signer {
                ed25519: a.signer,
            });
        crate::op::Operation::new(repo.clone(), principal, auth, kind)
    };
    let write = crate::op::OpKind::UpdateRef(upd(HEAD, Missing, A));
    let signed = op(write.clone(), Some(auth.clone()));
    let mut input = AdmissionInput::new(&signed);
    assert_eq!(input.idempotency_key, Some(auth.nonce.as_str()));
    assert_eq!((input.declared_bytes, input.pack_id), (0, None));
    assert!(charges_for(&input).is_empty(), "no configured quota");
    input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
    let scope = QuotaScope::for_signer(&repo.namespace, &auth.signer);
    let expected = QuotaCharge {
        scope,
        bytes: 0,
        limits: crate::quota::DEFAULT_WRITE_QUOTA,
    };
    assert_eq!(charges_for(&input), vec![expected]);
    let read = crate::op::OpKind::ReadRef { name: HEAD.into() };
    for other in [op(write, None), op(read, Some(auth))] {
        let mut input = AdmissionInput::new(&other);
        input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
        assert!(charges_for(&input).is_empty());
    }
}

#[test]
fn single_partition_maps_everything_to_the_namespace() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let expected = Partition::Namespace(NamespaceKey::deployment_default());
    let shards = SinglePartition;
    assert_eq!(shards.ref_shard(&repo, HEAD), expected);
    assert_eq!(shards.ref_shard(&repo, PACKMAP), expected);
    assert_eq!(shards.coordinator(&repo.namespace), expected);
    assert_eq!(shards.ref_index(&repo, HEAD), expected);
    assert_eq!(shards.membership(&repo, &PackKey::new(A).into()), expected);
}

// ----------------------------------------------- deadline and re-plans

/// Move the store clock past the deadline before the first `n` applies.
fn late(
    clock: &Arc<ManualClock>,
    n: u32,
) -> impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync + use<> {
    let (clock, left) = (clock.clone(), AtomicU32::new(n));
    move |_, _, _| {
        if left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
            .is_ok()
        {
            clock.advance(i64::try_from(WINDOW).unwrap() + 1);
        }
    }
}

#[test]
fn late_batch_fails_not_after_and_replans() {
    for auth in [authv2(), AuthMode::Open] {
        for (late_applies, ok) in [(1, true), (2, false)] {
            let clock = clock();
            let spy = Spy::new(store(&clock)).hook(late(&clock, late_applies));
            let env = build(cfg(auth.clone()), spy, Hooks::new(), clock);
            let u = upd(HEAD, Missing, A);
            let req = match env.pipe.cfg.auth {
                AuthMode::Open => Req::unsigned(Procedure::UpdateRef),
                _ => Req::update(&key(7), 1, &u, T0),
            };
            let result = env.update(&req, &u);
            if ok {
                assert_eq!(result.unwrap(), UpdateRefResult::Committed);
                assert_eq!(env.batches().len(), 2);
            } else {
                // Re-planned once, then `unavailable`, never `aborted`.
                let err = result.unwrap_err();
                assert_eq!(err.code(), Code::Unavailable);
                assert!(env.rows().is_empty(), "a late batch never commits");
            }
        }
    }
}

#[test]
fn not_after_ignores_test_clock_skew() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let mut a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
    a.business_skew_ms = 3_600_000;
    block_on(env.pipe.update_ref(&a, u)).unwrap();
    let batch = &env.batches()[0];
    assert_eq!(
        batch.preconditions[0],
        Precondition::NotAfter(ms(T0) + WINDOW)
    );
    // Business time (the quota window) does move.
    let rows = env.rows();
    let (_, quota) = rows
        .iter()
        .find(|(k, _)| k.as_bytes().starts_with(b"q\0"))
        .unwrap();
    let state = codec::decode_quota_state(quota).unwrap();
    assert_eq!(state.window_start, T0 + 3_600_000);
}

/// Toggle the layout version key before the first `n` applies: a
/// concurrent writer that breaks one of the plan's guards.
fn interfere(n: u32) -> impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync {
    let left = AtomicU32::new(n);
    move |kv, p, _| {
        if left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
            .is_ok()
        {
            let v = keys::layout_version();
            let batch = if now(kv.get(p, &v)).unwrap().is_some() {
                Batch::new().delete(v)
            } else {
                Batch::new().put(v, codec::encode_u32(LAYOUT_VERSION))
            };
            now(kv.apply(p, batch)).unwrap();
        }
    }
}

#[test]
fn replan_after_concurrent_writer_then_succeeds() {
    let clock = clock();
    let spy = Spy::new(store(&clock)).hook(interfere(MAX_REPLAN));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    assert_eq!(
        env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.batches().len(),
        usize::try_from(MAX_REPLAN).unwrap() + 1
    );
}

#[test]
fn replan_exhaustion_is_aborted_retryable() {
    let clock = clock();
    let spy = Spy::new(store(&clock)).hook(interfere(MAX_REPLAN + 1));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Aborted);
    assert!(err.code().is_retryable());
    assert_eq!(env.read(HEAD), None);
    // The retry with the same nonce commits.
    assert_eq!(env.update(&req, &u).unwrap(), UpdateRefResult::Committed);
}

#[test]
fn concurrent_duplicate_returns_the_winners_result() {
    // Another request with the same nonce commits between plan and apply:
    // the loser's replay guard fails and it answers with the winner's result.
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let auth = env(authv2()).auth(&req).unwrap().auth.unwrap();
    let won = StoredResult::UpdateRef(UpdateRefResult::Conflict { current: Some(C) });
    let record = ReplayRecord {
        fingerprint: auth.fingerprint,
        expires_at_ms: auth.expires_at_ms,
        state: ReplayState::Committed(won),
    };
    let fired = std::sync::atomic::AtomicBool::new(false);
    let hook = move |kv: &MemoryKv, p: &Partition, _: &Batch| {
        if !fired.swap(true, Ordering::SeqCst) {
            let key = keys::replay(&auth.replay_scope);
            let batch = Batch::new().put(key, codec::encode_replay_record(&record));
            now(kv.apply(p, batch)).unwrap();
        }
    };
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)).hook(hook),
        Hooks::new(),
        clock,
    );
    let result = env.update(&req, &u).unwrap();
    assert_eq!(result, UpdateRefResult::Conflict { current: Some(C) });
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn store_full_maps_to_unavailable() {
    let clock = clock();
    // Two expired replay entries the write's prune deletes.
    let expired = || {
        [[5u8; 32], [6; 32]].iter().fold(Batch::new(), |b, scope| {
            b.put(keys::replay_expiry(1, scope), Value::default())
                .put(keys::replay(scope), Value::new(vec![1]))
        })
    };
    let probe = store(&clock);
    now(probe.apply(&ns(), expired())).unwrap();
    let used = now(probe.stats(&ns())).unwrap().bytes;
    // The same rows under a cap they almost fill.
    let kv = store(&clock).with_capacity_limit(used + 8);
    now(kv.apply(&ns(), expired())).unwrap();
    let env = build(cfg(authv2()), Spy::new(kv), Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    let n = nonce_where(&env, &key(7), true, 1);
    let err = env
        .update(&Req::update(&key(7), n, &u, T0), &u)
        .unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unavailable, "storage partition full")
    );
    assert_eq!(METRIC_PARTITION_FULL, "mkit_server_partition_full_total");
    assert_eq!(env.metrics.count(METRIC_PARTITION_FULL), 1);
    assert!(env.metrics.0.lock().unwrap().contains(&(
        METRIC_PARTITION_FULL,
        vec![("kind".into(), "namespace".into())]
    )));
    // The prune ran as a delete-only batch; nothing else was written.
    assert!(env.rows().is_empty(), "{:?}", env.rows());
}

#[test]
fn dropped_request_future_leaves_no_partial_state() {
    let u = upd(HEAD, Missing, A);
    let (pre, post) = {
        let env = env(authv2());
        let before = env.rows();
        env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap();
        (before, env.rows())
    };
    for polls in 0.. {
        let clock = clock();
        let mut spy = Spy::new(store(&clock));
        spy.yields = true;
        let env = build(cfg(authv2()), spy, Hooks::new(), clock);
        let a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
        let mut fut = Box::pin(env.pipe.update_ref(&a, u.clone()));
        let mut done = false;
        for _ in 0..polls {
            if fut
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                done = true;
                break;
            }
        }
        drop(fut);
        let rows = env.rows();
        assert!(rows == pre || rows == post, "after {polls} polls");
        if done {
            assert_eq!(rows, post);
            break;
        }
    }
}

#[test]
fn list_refs_strips_prefix_and_paginates() {
    let clock = clock();
    let mut cfg = cfg(AuthMode::Open);
    cfg.list_page_limit = 2;
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let names = ["a", "b", "c", "d", "e"].map(|n| format!("refs/heads/{n}"));
    let mut refs: Vec<_> = names.iter().map(|n| (n.as_str(), A)).collect();
    refs.push(("refs/tags/v1", B));
    seed(env.pipe.meta.inner.as_ref(), &refs);
    let a = env.auth(&Req::unsigned(Procedure::ListRefs)).unwrap();
    let listed = block_on(env.pipe.list_refs(&a, "refs/heads/")).unwrap();
    let got: Vec<_> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(got, ["a", "b", "c", "d", "e"]);
    assert_eq!(block_on(env.pipe.list_refs(&a, "")).unwrap().len(), 6);
    assert_eq!(
        code(block_on(env.pipe.list_refs(&a, "/"))),
        Code::InvalidArgument
    );
    // Five refs at two per page is three scans.
    let scans = env.pipe.meta.seen.lock().unwrap().len();
    assert_eq!(scans, 3 + 3);
}

/// SPEC-REFS §4: a prefix matches at a path-component boundary, with or
/// without trailing `/`s, and the prefix plus its `/` is stripped; this is
/// what `mkit serve` (`FileTransport`'s directory walk) answers.
#[test]
fn list_refs_prefix_matches_at_component_boundaries() {
    let clock = clock();
    let mut cfg = cfg(AuthMode::Open);
    cfg.list_page_limit = 1;
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let refs = [
        ("refs/heads/feat/x", A),
        ("refs/heads/featx", B),
        ("refs/heads/main", C),
        ("refs/headsx/y", A),
        ("refs/tags/v1", B),
    ];
    seed(env.pipe.meta.inner.as_ref(), &refs);
    let a = env.auth(&Req::unsigned(Procedure::ListRefs)).unwrap();
    let list = |prefix: &str| -> Vec<String> {
        let listed = block_on(env.pipe.list_refs(&a, prefix)).unwrap();
        listed.into_iter().map(|e| e.name).collect()
    };
    let heads = ["feat/x", "featx", "main"];
    assert_eq!(list("refs/heads"), heads);
    assert_eq!(list("refs/heads/"), heads);
    assert_eq!(list("refs/heads//"), heads);
    assert_eq!(list("refs/heads/feat"), ["x"]);
    assert_eq!(list("refs/heads/feat/"), ["x"]);
    assert_eq!(list("refs/heads/ma"), Vec::<String>::new());
    // A ref named exactly the prefix is not listed.
    assert_eq!(list("refs/heads/main"), Vec::<String>::new());
    let all = [
        "heads/feat/x",
        "heads/featx",
        "heads/main",
        "headsx/y",
        "tags/v1",
    ];
    assert_eq!(list("refs"), all);
    assert_eq!(list("refs/"), all);
    assert_eq!(list("refs//"), all);
    assert_eq!(list("").len(), refs.len());
    assert_eq!(list("nope/"), Vec::<String>::new());
    // A prefix over the ref-name limit is refused, not silently empty.
    let long = format!("refs/{}", "a".repeat(refs::MAX_REF_NAME_BYTES));
    let err = block_on(env.pipe.list_refs(&a, &long)).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.public_message(), refs::REF_NAME_TOO_LONG);
}

/// SPEC-REFS §3: a ref name is at most 512 bytes; a longer one is refused
/// with its own message on reads and writes.
#[test]
fn over_long_ref_names_are_refused_explicitly() {
    let env = env(AuthMode::Open);
    let longest = format!("refs/heads/{}", "a".repeat(refs::MAX_REF_NAME_BYTES - 11));
    let over = format!("{longest}a");
    assert_eq!(
        env.open_update(&upd(&longest, Missing, A)).unwrap(),
        UpdateRefResult::Committed
    );
    for err in [env.open_update(&upd(&over, Missing, A)).unwrap_err(), {
        let a = env.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
        block_on(env.pipe.read_ref(&a, &over)).unwrap_err()
    }] {
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.public_message(), refs::REF_NAME_TOO_LONG);
    }
    let a = env.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
    assert_eq!(block_on(env.pipe.read_ref(&a, &longest)).unwrap(), Some(A));
}

/// R-86: the pipeline serves only `refs/` names (SPEC-REFS §2); a valid
/// name outside it is refused by name on reads and writes, and nothing is
/// stored.
#[test]
fn ref_names_outside_refs_are_refused_explicitly() {
    let env = env(AuthMode::Open);
    let before = env.rows();
    let read = |name: &str| {
        let a = env.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
        block_on(env.pipe.read_ref(&a, name)).unwrap_err()
    };
    let advance = |head: &str| {
        let req = Req::unsigned(Procedure::AdvanceRefs);
        env.advance(&req, &upd(head, Missing, A), &upd(PACKMAP, Missing, B))
            .unwrap_err()
    };
    for name in ["main", "heads/main", "packs/x", "refsx/y"] {
        for err in [
            env.open_update(&upd(name, Missing, A)).unwrap_err(),
            read(name),
            advance(name),
        ] {
            assert_eq!(err.code(), Code::InvalidArgument, "{name}");
            assert_eq!(err.public_message(), refs::REF_NAME_OUTSIDE_REFS, "{name}");
        }
    }
    // A grammar failure keeps its own message.
    let err = read("main/.x");
    assert_eq!(err.public_message(), "ref name is invalid (SPEC-REFS §3)");
    assert_eq!(env.rows(), before, "nothing was stored");
}

#[test]
fn store_error_is_redacted() {
    let clock = clock();
    let kv = store(&clock).with_fault(MemoryFault::ApplyBefore);
    let env = build(cfg(AuthMode::Open), Spy::new(kv), Hooks::new(), clock);
    let err = env.open_update(&upd(HEAD, Missing, A)).unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.public_message(), "ref store request failed");
    for shown in [format!("{err}"), format!("{err:?}")] {
        assert!(!shown.contains("injected"), "{shown}");
    }
    assert!(err.log_detail().unwrap().contains("injected"));
}

type AdmissionSeen = (Option<String>, u64, Option<QuotaLimits>);

#[derive(Default)]
struct SpyAdmission(Mutex<Vec<AdmissionSeen>>);

impl Admission for SpyAdmission {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let seen = (
            input.idempotency_key.map(str::to_owned),
            input.declared_bytes,
            input.write_quota,
        );
        self.0.lock().unwrap().push(seen);
        DefaultAdmission.admit(input).await
    }
}

#[test]
fn admission_input_carries_nonce_and_declared_bytes() {
    let clock = clock();
    let hooks = with_admission(SpyAdmission::default());
    let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 9, &u, T0);
    env.update(&req, &u).unwrap();
    env.update(&req, &u).unwrap(); // a replay never reaches admission
    let seen = env.pipe.hooks.admission.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(Some(nonce(9)), 0, Some(crate::quota::DEFAULT_WRITE_QUOTA))]
    );
}

#[test]
fn replay_and_quota_rows_shrink_after_load() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 1_000,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let write = |signer: u8, n: u32| {
        let u = upd(&format!("refs/heads/s{signer}-{n}"), Missing, A);
        let created = env.clock.now_ms();
        env.update(&Req::update(&key(signer), n, &u, created), &u)
            .unwrap();
    };
    for n in 0..500 {
        write(u8::try_from(n % 50).unwrap(), n);
    }
    let counts = |env: &Env| ["p", "px", "q", "qx"].map(|t| env.count(t));
    let baseline = counts(&env);
    assert_eq!(baseline, [500, 500, 50, 50]);
    // Past the envelope window plus the prune grace, and two quota windows.
    env.clock.advance(300_000 + 60_000 + 120_000 + 1);
    // One write in eight runs the prune, of up to PRUNE_LIMIT rows each.
    for n in 500..580 {
        write(200, n);
    }
    let after = counts(&env);
    for (a, b) in after.iter().zip(baseline) {
        assert!(*a <= b, "{after:?} vs {baseline:?}");
    }
    assert_eq!(after[2..], [1, 1], "every stale quota window pruned");
}

// ------------------------------------------------- telemetry and misc

#[test]
fn metrics_count_requests_by_code_and_dropped_headers() {
    let env = env(AuthMode::Open);
    env.open_update(&upd(HEAD, Missing, A)).unwrap();
    let _ = env.open_update(&upd("refs/heads/..", Missing, A));
    let requests: Vec<_> = env
        .metrics
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(n, _)| *n == METRIC_REQUESTS)
        .map(|(_, labels)| labels.clone())
        .collect();
    let label = |code: &str| {
        vec![
            ("procedure".to_owned(), "UpdateRef".to_owned()),
            ("code".to_owned(), code.to_owned()),
        ]
    };
    assert_eq!(requests, vec![label("ok"), label("invalid_argument")]);
    let err = env
        .pipe
        .with_header(ServerError::unavailable("x"), "Retry-After", "1");
    let err = env.pipe.with_header(err, "Bad Name", "v");
    assert_eq!(err.headers().len(), 1);
    assert_eq!(env.metrics.count(METRIC_HEADER_DROPPED), 1);
}

#[test]
fn health_probes_both_stores() {
    let env = env(AuthMode::Open);
    assert!(block_on(env.pipe.health()).is_healthy());
}

#[test]
fn entry_futures_are_send() {
    fn send<T: Send>(_: &T) {}
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
    send(&env.pipe.update_ref(&a, u));
    send(&env.pipe.list_refs(&a, ""));
}

fn ms(t: i64) -> u64 {
    u64::try_from(t).unwrap()
}

#[test]
fn plan_signed_conflict_still_charges_quota() {
    let name = repo_name();
    let refs = [upd(HEAD, Missing, C)];
    let charges = [charge(5)];
    let req = WriteRequest {
        authority_generation: None,
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        ref_index: None,
        replay: Some(replay()),
        charges: &charges,
        namespace_charge: None,
        grant: None,
        layout_version: false,
        mark_repo_known: false,
        lease: None,
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let values = [ref_value(HEAD, A)];
    let clock = clock_at(ms(T0), None);
    let Planned::Apply(plan) = plan_write(&req, &snapshot(&req, &values), &clock).unwrap() else {
        panic!("a signed conflict is stored");
    };
    let conflict = UpdateRefResult::Conflict { current: Some(A) };
    assert_eq!(plan.on_commit, StoredResult::UpdateRef(conflict));
    let quota = keys::quota(&charges[0].scope);
    let after = plan.batch.writes.iter().find_map(|w| match w {
        Write::Put(k, v) if *k == quota => Some(codec::decode_quota_state(v).unwrap()),
        _ => None,
    });
    let one = QuotaState {
        window_start: T0,
        ops: 1,
        bytes: 0,
    };
    assert_eq!(after, Some(one));
    assert!(
        plan.batch
            .preconditions
            .contains(&Precondition::Absent(quota))
    );
    let ref_key = keys::ref_key(&name, HEAD);
    let moved = plan
        .batch
        .writes
        .iter()
        .any(|w| matches!(w, Write::Put(k, _) if *k == ref_key));
    assert!(!moved, "the ref stays");
}

#[test]
fn plan_prune_fits_the_batch_op_cap() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Any, C), upd(HEAD, Any, C)];
    let charges: Vec<_> = (0u8..4)
        .map(|i| QuotaCharge {
            scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[i; 32]),
            ..charge(5)
        })
        .collect();
    let req = WriteRequest {
        authority_generation: None,
        repo: &name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        ref_index: None,
        replay: Some(replay()),
        charges: &charges,
        namespace_charge: None,
        grant: None,
        layout_version: true,
        mark_repo_known: false,
        lease: None,
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let mut snap = snapshot(&req, &[]);
    let limit = usize::try_from(PRUNE_LIMIT).unwrap();
    for i in 0..limit {
        let old = [u8::try_from(100 + i).unwrap(); 32];
        snap.expired_replays
            .push((keys::replay_expiry(1, &old), keys::replay(&old)));
        let scope = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &old);
        let state = QuotaState {
            window_start: 5,
            ops: 1,
            bytes: 0,
        };
        let quota = keys::quota(&scope);
        snap.insert(quota.clone(), Some(codec::encode_quota_state(&state)));
        snap.stale_quotas
            .push((keys::quota_window(5, &scope), quota));
    }
    let Planned::Apply(plan) = plan_write(&req, &snap, &clock_at(ms(T0), None)).unwrap() else {
        panic!("a write");
    };
    let ops = plan.batch.preconditions.len() + plan.batch.writes.len();
    assert!(ops <= crate::store::MAX_BATCH_OPS, "{ops}");
    assert!(plan.batch.validate(&StoreCapabilities::full()).is_ok());
    let prune = plan.prune.unwrap();
    assert!(prune.writes.len() >= 2 * limit, "every replay pair fits");
    // Prune guards come last, from `prune_from` on.
    let guards = &plan.batch.preconditions[plan.prune_from..];
    assert_eq!(guards, &prune.preconditions[1..]);
    assert!(guards.iter().all(|p| matches!(p, Precondition::Equals(..))));
}

#[test]
fn prune_sampling_is_deterministic_one_in_eight() {
    let name = repo_name();
    let refs = [upd(HEAD, Any, C)];
    let request = |replay: Option<ReplayGuard>| WriteRequest {
        authority_generation: None,
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        ref_index: None,
        replay,
        charges: &[],
        namespace_charge: None,
        grant: None,
        layout_version: false,
        mark_repo_known: false,
        lease: None,
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let sampled = (0u8..=255)
        .filter(|b| {
            let scoped = ReplayGuard {
                scope: [*b; 32],
                ..replay()
            };
            prune_sampled(&request(Some(scoped)), 3)
        })
        .count();
    assert_eq!(sampled, 256 / 8);
    assert!(!prune_sampled(&request(None), 8), "nothing to prune");
}

#[test]
fn admission_allow_constructor() {
    let decision = AdmissionDecision::allow(vec![charge(1)]).with_reservation("r-1");
    let AdmissionDecision::Allow {
        charges,
        reservation,
        ..
    } = decision
    else {
        panic!("allow");
    };
    assert_eq!(
        (charges, reservation),
        (vec![charge(1)], Some("r-1".into()))
    );
    let deny = AdmissionDecision::Deny(crate::ServerError::permission_denied("no"));
    assert!(matches!(
        deny.with_reservation("x"),
        AdmissionDecision::Deny(_)
    ));
}

// ---------------------------------------------- review: round trips etc.

#[test]
fn signed_write_costs_two_backend_calls_in_steady_state() {
    let env = env(authv2());
    let k = key(7);
    let mut measured = Vec::new();
    let mut n = 0;
    for (i, sampled) in [false, false, true, false].into_iter().enumerate() {
        n = nonce_where(&env, &k, sampled, n + 1);
        let u = upd(&format!("refs/heads/b{i}"), Missing, A);
        let before = env.pipe.meta.calls();
        env.update(&Req::update(&k, n, &u, T0), &u).unwrap();
        measured.push((sampled, env.pipe.meta.calls() - before));
    }
    // One get_many and one apply; a sampled write adds its two prune scans.
    assert_eq!(measured, [(false, 2), (false, 2), (true, 4), (false, 2)]);
    // A replay is one read and no apply.
    let u = upd("refs/heads/b0", Missing, A);
    let first = nonce_where(&env, &k, false, 1);
    let before = env.pipe.meta.calls();
    env.update(&Req::update(&k, first, &u, T0), &u).unwrap();
    assert_eq!(env.pipe.meta.calls() - before, 1);
}

#[test]
fn signed_deadline_is_capped_by_the_envelope() {
    // A long apply window: the envelope cap binds.
    let first = clock();
    let mut long = cfg(authv2());
    long.max_apply_window = Duration::from_mins(2);
    let env = build(long, Spy::new(store(&first)), Hooks::new(), first);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    env.clock.set(T0 + 290_000);
    env.update(&req, &u).unwrap();
    let expires = ms(T0) + 300_000;
    let cap = expires + MAX_CLOCK_LEAD_MS.unsigned_abs();
    assert_eq!(
        env.batches()[0].preconditions[0],
        Precondition::NotAfter(cap)
    );

    // A late batch whose envelope expired meanwhile is not re-planned.
    let clock = clock();
    clock.set(T0 + 295_000);
    let spy = Spy::new(store(&clock)).hook(late(&clock, 1));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(env.batches().len(), 1);
    assert!(env.rows().is_empty());
}

#[test]
fn deny_with_402_but_no_challenge_detail_is_403() {
    let paid = ServerError::permission_denied("pay").with_http_status(402);
    let challenge = ServerError::admission_challenge(bytes::Bytes::from_static(b"c"));
    for denial in [paid, challenge] {
        let clock = clock();
        let hooks = with_admission(Fixed(AdmissionDecision::Deny(denial)));
        let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
        let u = upd(HEAD, Missing, A);
        let err = env
            .update(&Req::update(&key(7), 1, &u, T0), &u)
            .unwrap_err();
        assert_eq!(
            (err.code(), err.http_status()),
            (Code::PermissionDenied, Some(403))
        );
        assert!(err.details().is_empty() && err.headers().is_empty());
        assert!(env.rows().is_empty());
    }
}

struct Granting;

impl Authorizer for Granting {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts {
            authority_generation: None,
            owner: true,
            grant: Some(crate::op::GrantRef {
                id: [9; 32],
                epoch: 0,
                presence_requirement: None,
            }),
            ..AuthzFacts::default()
        })
    }
}

#[derive(Default)]
struct SeesAuthz(Mutex<Option<AuthzFacts>>);

impl Admission for SeesAuthz {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        *self.0.lock().unwrap() = Some(input.op.authz.clone());
        Ok(AdmissionDecision::allow(Vec::new()))
    }
}

#[test]
fn authorizer_facts_reach_admission_and_apply() {
    let clock = clock();
    let hooks = Hooks {
        authorizer: Granting,
        admission: SeesAuthz::default(),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
    let u = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap();
    let seen = env.pipe.hooks.admission.0.lock().unwrap().clone().unwrap();
    assert!(seen.owner);
    assert_eq!(seen.grant.map(|g| g.epoch), Some(0));
    // The grant's epoch is required at apply: absent means epoch 0.
    let guard = Precondition::Absent(keys::grant_epoch());
    assert!(env.batches()[0].preconditions.contains(&guard));
}

#[test]
fn lost_prune_race_retries_without_prune_uncounted() {
    let clock = clock();
    let other = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[42; 32]);
    let quota = keys::quota(&other);
    let stale = QuotaState {
        window_start: 1,
        ops: 1,
        bytes: 0,
    };
    let kv = store(&clock);
    let seed_batch = Batch::new()
        .put(quota.clone(), codec::encode_quota_state(&stale))
        .put(keys::quota_window(1, &other), Value::default());
    now(kv.apply(&ns(), seed_batch)).unwrap();
    // Apply 0: another writer moves the stale quota row (the prune guard
    // fails). Applies 1..=MAX_REPLAN: a real guard breaks each time.
    let (applies, layout) = (AtomicU32::new(0), interfere(MAX_REPLAN));
    let race = quota.clone();
    let hook = move |kv: &MemoryKv, p: &Partition, batch: &Batch| {
        if applies.fetch_add(1, Ordering::SeqCst) == 0 {
            let moved = QuotaState { ops: 2, ..stale };
            let bump = Batch::new().put(race.clone(), codec::encode_quota_state(&moved));
            now(kv.apply(p, bump)).unwrap();
        } else {
            layout(kv, p, batch);
        }
    };
    let env = build(cfg(authv2()), Spy::new(kv).hook(hook), Hooks::new(), clock);
    let n = nonce_where(&env, &key(7), true, 1);
    let u = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), n, &u, T0), &u).unwrap();
    let batches = env.batches();
    assert_eq!(batches.len(), usize::try_from(MAX_REPLAN).unwrap() + 2);
    let deletes = |b: &Batch| b.writes.iter().any(|w| matches!(w, Write::Delete(_)));
    assert!(deletes(&batches[0]), "the first attempt prunes");
    assert!(!batches[1..].iter().any(deletes), "the retries do not");
    let kept = now(env.pipe.meta.inner.get(&ns(), &quota)).unwrap();
    assert!(kept.is_some(), "the raced row is not pruned");
}

#[path = "tests_stream.rs"]
mod stream;

#[test]
fn single_repository_header_rules_preserve_04_requests_and_fail_at_stage_zero() {
    let env = env(authv2());
    // 0.4.x reads carry no header, and signed writes carry the configured identity.
    assert_eq!(env.read(HEAD), None);
    let calls_before = env.pipe.meta.calls();
    let u = upd(HEAD, Missing, A);
    let signed = Req::update(&key(7), 1, &u, T0);
    let mut absent = signed.clone();
    absent.headers.retain(|(n, _)| *n != "x-repository");
    for value in [None, Some("")] {
        let mut request = absent.clone();
        if let Some(value) = value {
            request = request.header("x-repository", value);
        }
        let err = env.auth(&request).unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(
            err.public_message(),
            "missing X-Repository on a signed request"
        );
    }
    let other = Req::unsigned(Procedure::ReadRef).header("x-repository", "other");
    assert_eq!(env.auth(&other).unwrap_err().code(), Code::NotFound);
    let bad = Req::unsigned(Procedure::ReadRef).header("x-repository", ".bad");
    assert_eq!(env.auth(&bad).unwrap_err().code(), Code::InvalidArgument);
    assert!(env.batches().is_empty());
    assert_eq!(env.pipe.meta.calls(), calls_before);
    assert_eq!(env.metrics.count(crate::METRIC_REQUESTS), 5);

    assert_eq!(env.update(&signed, &u).unwrap(), UpdateRefResult::Committed);
    assert_eq!(env.read(HEAD), Some(A));
}

#[test]
fn d34_advance_pairing_rejected_before_storage_and_replay() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.sharding = Sharding::D34;
    let env = build(config, Spy::new(store(&clock)), Hooks::new(), clock);
    let pairs = [
        ("refs/heads/f", "refs/mkit/packmap/g"),
        ("refs/heads/f", "refs/packmaps/f"),
        ("refs/tags/t", "refs/mkit/packmap/t"),
        ("refs/heads/F", "refs/mkit/packmap/f"),
    ];
    for (i, (head, packmap)) in pairs.into_iter().enumerate() {
        let request = Req::signed(
            &key(7),
            Procedure::AdvanceRefs,
            b"pair",
            &nonce(u32::try_from(i).unwrap()),
            T0,
        );
        let auth = env.auth(&request).unwrap();
        let err = block_on(env.pipe.advance_refs(
            &auth,
            upd(head, Missing, A),
            upd(packmap, Missing, B),
        ))
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.public_message(),
            "AdvanceRefs pairs refs/heads/<x> with refs/mkit/packmap/<x> on this server"
        );
        assert_eq!(env.pipe.meta.calls(), 0);
        assert!(env.batches().is_empty());
        let replay = keys::replay(&auth.auth.as_ref().unwrap().replay_scope);
        for name in [head, packmap] {
            let p = env.pipe.shards.ref_shard(&repo(), name);
            assert_eq!(now(env.pipe.meta.inner.get(&p, &replay)).unwrap(), None);
            assert!(
                now(env.pipe.meta.inner.scan(
                    &p,
                    &Key::default(),
                    &Key::new(vec![0xff]),
                    None,
                    100
                ))
                .unwrap()
                .entries
                .is_empty()
            );
        }
    }
}

#[test]
fn d34_canonical_advance_commits_in_one_ref_partition() {
    let clock = clock();
    let partitions = Arc::new(Mutex::new(Vec::new()));
    let recorded = partitions.clone();
    let meta = Spy::new(store(&clock)).hook(move |_, p, batch| {
        recorded.lock().unwrap().push((p.clone(), batch.clone()));
    });
    let mut config = cfg(authv2());
    config.sharding = Sharding::D34;
    let env = build(config, meta, Hooks::new(), clock);
    let head = "refs/heads/f";
    let packmap = "refs/mkit/packmap/f";
    // Choose an unsampled replay scope so the store-call assertion pins the hot path.
    let request = (0..100)
        .map(|n| Req::signed(&key(7), Procedure::AdvanceRefs, b"canonical", &nonce(n), T0))
        .find(|r| {
            !env.auth(r).unwrap().auth.as_ref().unwrap().replay_scope[0]
                .is_multiple_of(PRUNE_SAMPLE)
        })
        .unwrap();
    assert_eq!(
        env.advance(&request, &upd(head, Missing, A), &upd(packmap, Missing, B))
            .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(
        env.pipe.meta.calls(),
        5,
        "renewal adds one source relay scan"
    );
    let applied = partitions.lock().unwrap();
    let refs: Vec<_> = applied
        .iter()
        .filter(|(p, _)| matches!(p, Partition::Ref { .. }))
        .collect();
    let [(p, batch)] = refs.as_slice() else {
        panic!("advance must use one batch")
    };
    let expected = Partition::Ref {
        ns: repo().namespace,
        repo: repo().name,
        shard_ref: head.into(),
    };
    assert_eq!(p, &expected);
    for (name, id) in [(head, A), (packmap, B)] {
        assert!(batch.writes.contains(&Write::Put(
            keys::ref_key(&repo().name, name),
            codec::encode_ref_id(&id)
        )));
        assert_eq!(
            now(read::read_ref(
                env.pipe.meta.inner.as_ref(),
                p,
                &repo().name,
                name
            ))
            .unwrap(),
            Some(id)
        );
    }
    assert!(
        now(env.pipe.meta.inner.get(
            p,
            &keys::replay(&env.auth(&request).unwrap().auth.unwrap().replay_scope)
        ))
        .unwrap()
        .is_some()
    );
    // Replay lookup returns before any hooks or extra store calls.
    let prior_batches = applied.len();
    drop(applied);
    let before = env.pipe.meta.calls();
    assert_eq!(
        env.advance(&request, &upd(head, Missing, A), &upd(packmap, Missing, B))
            .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.pipe.meta.calls() - before, 1);
    assert_eq!(partitions.lock().unwrap().len(), prior_batches);
}

fn prune_race_then_push(kv: MemoryKv, pushed: codec::EpochLease) -> Spy {
    let scope = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[42; 32]);
    let quota = keys::quota(&scope);
    let stale = QuotaState {
        window_start: 1,
        ops: 1,
        bytes: 0,
    };
    let index = keys::quota_window(1, &scope);
    let raced_quota = quota.clone();
    let prune_index = index.clone();
    let mut meta = Spy::new(kv).hook(move |store, p, batch| {
        if batch.writes.contains(&Write::Delete(prune_index.clone())) {
            assert_eq!(
                now(store.apply(
                    p,
                    Batch::new().put(
                        raced_quota.clone(),
                        codec::encode_quota_state(&QuotaState { ops: 2, ..stale })
                    )
                ))
                .unwrap(),
                BatchOutcome::Committed
            );
        }
    });
    meta.after_hook = Some(Box::new(move |store, p, batch, outcome| {
        if batch.writes.contains(&Write::Delete(index.clone())) {
            let BatchOutcome::PreconditionFailed { index: failed, .. } = outcome else {
                panic!("prune guard must fail")
            };
            assert_eq!(
                batch.preconditions[*failed],
                Precondition::Equals(quota.clone(), codec::encode_quota_state(&stale))
            );
            assert_eq!(
                now(store.apply(
                    p,
                    Batch::new().put(keys::epoch_lease(), codec::encode_epoch_lease(&pushed))
                ))
                .unwrap(),
                BatchOutcome::Committed
            );
        }
    }));
    meta
}

#[test]
fn d34_prune_retry_refreshes_the_epoch_even_without_a_counted_replan() {
    let clock = clock();
    let pushed = codec::EpochLease {
        authority_generation: None,
        epoch: 1,
        expires_at_ms: ms(T0) + 30_000,
        config_version: 1,
    };
    let meta = prune_race_then_push(store(&clock), pushed);
    let scope = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[42; 32]);
    let stale = QuotaState {
        window_start: 1,
        ops: 1,
        bytes: 0,
    };
    let mut config = cfg(AuthMode::Open);
    config.sharding = Sharding::D34;
    let env = build(config, meta, Hooks::new(), clock);
    let p = D34Shards.ref_shard(&repo(), HEAD);
    let old = codec::EpochLease {
        authority_generation: None,
        epoch: 0,
        ..pushed
    };
    assert_eq!(
        now(env.pipe.meta.inner.apply(
            &p,
            Batch::new()
                .put(keys::epoch_lease(), codec::encode_epoch_lease(&old))
                .put(keys::quota_window(1, &scope), Value::default())
                .put(keys::quota(&scope), codec::encode_quota_state(&stale))
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
    let refs = [upd(HEAD, Any, C)];
    let charges = [QuotaCharge {
        scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[43; 32]),
        bytes: 0,
        limits: DEFAULT_WRITE_QUOTA,
    }];
    let req = WriteRequest {
        authority_generation: None,
        repo: &repo_name(),
        kind: WriteKind::UpdateRef,
        refs: &refs,
        ref_index: None,
        replay: Some(ReplayGuard {
            scope: [0; 32],
            fingerprint: [1; 32],
            expires_at_ms: T0 + 100_000,
        }),
        charges: &charges,
        namespace_charge: None,
        grant: Some(crate::op::GrantRef {
            id: [9; 32],
            epoch: 0,
            presence_requirement: None,
        }),
        layout_version: false,
        mark_repo_known: false,
        lease: Some(lease::LeaseWrite {
            value: old,
            install: false,
        }),
        rejection: None,
        pending: None,
        begin: None,
        advance: None,
        implicit: None,
    };
    let ahead = snapshot(
        &req,
        &[(keys::epoch_lease(), codec::encode_epoch_lease(&old))],
    );
    let a = env.auth(&Req::unsigned(Procedure::UpdateRef)).unwrap();
    let op = env
        .pipe
        .identify(&a, OpKind::UpdateRef(refs[0].clone()))
        .unwrap();
    assert_eq!(
        block_on(env.pipe.apply_loop(&op, &a, &p, &req, Some(ahead)))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        env.batches().len(),
        1,
        "the old grant fails planning before the retry applies"
    );
    assert_eq!(
        now(env
            .pipe
            .meta
            .inner
            .get(&p, &keys::ref_key(&repo_name(), HEAD)))
        .unwrap(),
        None
    );
    assert_eq!(
        now(env.pipe.meta.inner.get(&p, &keys::epoch_lease())).unwrap(),
        Some(codec::encode_epoch_lease(&pushed))
    );
}

#[test]
fn epoch_lease_configuration_refuses_zero_margin_and_insufficient_budget() {
    for (lease, margin, budget, valid) in [
        (30_000, 5_000, 1_000, true),
        (6_001, 5_000, 1_000, true),
        (6_000, 5_000, 1_000, false),
        (30_000, 0, 1_000, false),
        (u64::MAX, u64::MAX, 1, false),
    ] {
        let clock = clock();
        let mut config = cfg(AuthMode::Open);
        config.epoch_lease_ms = lease;
        config.lease_margin_ms = margin;
        config.min_lease_budget_ms = budget;
        let result = Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock),
            Hooks::new(),
            config,
            clock,
            Arc::new(SpyMetrics::default()),
        );
        assert_eq!(result.is_ok(), valid);
        if !valid {
            assert_eq!(result.unwrap_err().code(), Code::InvalidArgument);
        }
    }
}

#[test]
fn single_signed_write_reads_the_epoch_directly_and_never_el() {
    let env = env(authv2());
    let update = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), 1, &update, T0), &update)
        .unwrap();
    let read = env.pipe.meta.seen.lock().unwrap();
    assert!(read.contains(&keys::grant_epoch()));
    assert!(!read.contains(&keys::epoch_lease()));
}

#[test]
fn leased_epoch_checks_use_the_granted_epoch_and_cap_replay_deadlines() {
    let env = env(AuthMode::Open);
    let name = repo_name();
    let refs = [upd(HEAD, Any, A)];
    let stored = codec::EpochLease {
        authority_generation: None,
        epoch: 6,
        expires_at_ms: ms(T0) + 30_000,
        config_version: 1,
    };
    for (expires_at_ms, expected) in [
        (ms(T0) + 30_000, ms(T0) + 2_500),
        (ms(T0) + 7_000, ms(T0) + 2_000),
    ] {
        let req = WriteRequest {
            authority_generation: None,
            repo: &name,
            kind: WriteKind::UpdateRef,
            refs: &refs,
            ref_index: None,
            replay: Some(ReplayGuard {
                expires_at_ms: T0 - MAX_CLOCK_LEAD_MS + 2_500,
                ..replay()
            }),
            charges: &[],
            namespace_charge: None,
            grant: Some(crate::op::GrantRef {
                id: [9; 32],
                epoch: 7,
                presence_requirement: None,
            }),
            layout_version: false,
            mark_repo_known: false,
            rejection: None,
            pending: None,
            begin: None,
            advance: None,
            implicit: None,
            lease: Some(lease::LeaseWrite {
                value: codec::EpochLease {
                    authority_generation: None,
                    epoch: 7,
                    expires_at_ms,
                    ..stored
                },
                install: true,
            }),
        };
        let clock = env.pipe.plan_clock(100_000, &req);
        assert_eq!(clock.deadline(), expected);
        let snap = snapshot(
            &req,
            &[(keys::epoch_lease(), codec::encode_epoch_lease(&stored))],
        );
        let Planned::Apply(plan) = plan_write(&req, &snap, &clock).unwrap() else {
            panic!("lease installation must apply")
        };
        assert_eq!(
            plan.batch.preconditions[0],
            Precondition::NotAfter(expected)
        );
        assert_eq!(plan.epoch_index, None);
        assert!(plan.batch.preconditions.contains(&Precondition::Equals(
            keys::epoch_lease(),
            codec::encode_epoch_lease(&stored)
        )));
        assert!(!req.read_keys().contains(&keys::grant_epoch()));
    }
}

#[test]
fn single_advance_preserves_noncanonical_served_pairing() {
    let env = env(AuthMode::Open);
    assert_eq!(
        env.advance(
            &Req::unsigned(Procedure::AdvanceRefs),
            &upd("refs/heads/f", Missing, A),
            &upd("refs/packmaps/f", Missing, B)
        )
        .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.batches().len(), 1);
    assert_eq!(
        now(read::read_ref(
            env.pipe.meta.inner.as_ref(),
            &ns(),
            &repo().name,
            "refs/heads/f"
        ))
        .unwrap(),
        Some(A)
    );
    assert_eq!(
        now(read::read_ref(
            env.pipe.meta.inner.as_ref(),
            &ns(),
            &repo().name,
            "refs/packmaps/f"
        ))
        .unwrap(),
        Some(B)
    );
}

#[cfg(feature = "test-faults")]
#[test]
fn lease_directives_parse_epochs_and_require_an_explicit_recovery_marker() {
    let directives = TestDirectives::from_headers(|name| match name {
        BUMP_EPOCH_HEADER => Some("42".into()),
        LEASE_RECOVERED_HEADER => Some("1".into()),
        _ => None,
    })
    .unwrap();
    assert_eq!(directives.bump_epoch, Some(42));
    assert!(directives.lease_recovered);
    for (header, value) in [
        (BUMP_EPOCH_HEADER, "-1"),
        (BUMP_EPOCH_HEADER, "18446744073709551616"),
        (LEASE_RECOVERED_HEADER, "0"),
    ] {
        let error = TestDirectives::from_headers(|name| (name == header).then(|| value.into()))
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
    }
}

#[test]
fn ref_hint_is_bounded_and_outside_auth_v2_canonical_headers() {
    let env = env(authv2());
    let update = upd(HEAD, Any, A);
    let signed = Req::update(&key(7), 1, &update, T0);
    for hint in [
        HEAD.to_owned(),
        "bad ref".to_owned(),
        "refs/heads/é".to_owned(),
        "x".repeat(refs::MAX_REF_NAME_BYTES),
    ] {
        let a = env
            .auth(&signed.clone().header("x-mkit-ref", &hint))
            .unwrap();
        assert_eq!(a.ref_hint.as_deref(), Some(hint.as_str()));
        assert_eq!(a.auth, env.auth(&signed).unwrap().auth);
    }
    let long = "x".repeat(refs::MAX_REF_NAME_BYTES + 1);
    assert_eq!(
        env.auth(&signed.header("x-mkit-ref", &long))
            .unwrap()
            .ref_hint,
        None
    );
    assert!(!crate::auth_v2::HEADER_NAMES.contains(&"x-mkit-ref"));
    assert!(
        crate::auth_v2::CORS_ALLOW_HEADERS
            .split(',')
            .any(|name| name.trim() == "x-mkit-ref")
    );
}

#[test]
fn partition_full_counter_labels_every_partition_kind() {
    let env = env(authv2());
    let namespace = NamespaceKey::deployment_default();
    let repo = RepoName::new("room-a").unwrap();
    for (partition, kind) in [
        (Partition::Namespace(namespace.clone()), "namespace"),
        (Partition::Coordinator(namespace.clone()), "coordinator"),
        (
            Partition::Ref {
                ns: namespace.clone(),
                repo: repo.clone(),
                shard_ref: HEAD.into(),
            },
            "ref",
        ),
        (
            Partition::RepoIndex {
                ns: namespace.clone(),
                repo: repo.clone(),
                prefix: 0,
            },
            "repo_index",
        ),
        (
            Partition::RefIndex {
                ns: namespace,
                repo,
                bucket: 0,
            },
            "ref_index",
        ),
        (Partition::ContentShard(0), "content"),
    ] {
        let error = now(env.pipe.partition_full(&partition, None));
        assert_eq!(error.code(), Code::Unavailable);
        assert!(env.metrics.0.lock().unwrap().contains(&(
            "mkit_server_partition_full_total",
            vec![("kind".into(), kind.into())]
        )));
    }
    assert_eq!(env.metrics.count(METRIC_PARTITION_FULL), 6);
}

// ------------------------------------------- review fixes (WP-3.2 / WP-3.3)

/// Allows with a fresh reservation id and a receipt header.
struct ReceiptReserved(&'static str, AtomicU32);
impl Admission for ReceiptReserved {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let n = self.1.fetch_add(1, Ordering::SeqCst);
        Ok(AdmissionDecision::allow(Vec::new())
            .with_reservation(format!("{}-{n}", self.0))
            .with_response_header("Payment-Receipt", "receipt"))
    }
}

fn reservation_row<H: HookSet>(env: &Env<H>, rid: &str) -> codec::ReservationV1 {
    let row = now(env.pipe.meta.get(&ns(), &keys::reservation(rid).unwrap()))
        .unwrap()
        .unwrap();
    codec::decode_reservation(&row).unwrap()
}

fn update_meta<H: HookSet>(
    env: &Env<H>,
    req: &Req,
    u: &RefUpdate,
) -> Result<(UpdateRefResult, ResponseMeta), ServerError> {
    block_on(env.pipe.update_ref_with_meta(&env.auth(req)?, u.clone()))
}

#[test]
fn same_nonce_loser_with_its_own_reservation_aborts_replay_race_without_receipt() {
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let auth = env(authv2()).auth(&req).unwrap().auth.unwrap();
    let record = ReplayRecord {
        fingerprint: auth.fingerprint,
        expires_at_ms: auth.expires_at_ms,
        state: ReplayState::Committed(StoredResult::UpdateRef(UpdateRefResult::Committed)),
    };
    let fired = AtomicBool::new(false);
    let hook = move |kv: &MemoryKv, p: &Partition, batch: &Batch| {
        // The winner commits its replay record just before the loser's apply.
        let is_final = batch.preconditions.iter().any(
            |pre| matches!(pre, Precondition::Absent(k) if *k == keys::replay(&auth.replay_scope)),
        );
        if is_final && !fired.swap(true, Ordering::SeqCst) {
            let batch = Batch::new().put(
                keys::replay(&auth.replay_scope),
                codec::encode_replay_record(&record),
            );
            now(kv.apply(p, batch)).unwrap();
        }
    };
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)).hook(hook),
        with_admission(ReceiptReserved("loser-rid", AtomicU32::new(0))),
        clock,
    );
    let err = update_meta(&env, &req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Aborted);
    assert!(err.headers().is_empty());
    assert_one_abort(&env, "loser-rid-0", codec::AbortReason::ReplayRace);
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn conflict_result_carries_no_receipt_headers() {
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(ReceiptReserved("receipt-rid", AtomicU32::new(0))),
        clock,
    );
    let first = upd(HEAD, Missing, A);
    let (result, meta) = update_meta(&env, &Req::update(&key(7), 1, &first, T0), &first).unwrap();
    assert_eq!(result, UpdateRefResult::Committed);
    assert!(!meta.headers().is_empty());
    let conflict = upd(HEAD, Missing, B);
    let (result, meta) =
        update_meta(&env, &Req::update(&key(7), 2, &conflict, T0), &conflict).unwrap();
    assert_eq!(result, UpdateRefResult::Conflict { current: Some(A) });
    assert!(meta.headers().is_empty());
}

#[test]
fn abort_under_shard_counter_contention_retries_and_keeps_its_reason() {
    let fired = AtomicBool::new(false);
    let hook = move |kv: &MemoryKv, p: &Partition, batch: &Batch| {
        // Another reservation settles on the same shard just before this
        // abort applies, moving `os` and `oc` under it.
        let is_abort = batch.preconditions.iter().any(|pre| {
            matches!(pre, Precondition::Equals(k, _) if *k == keys::reservation("busy-rid").unwrap())
        });
        if is_abort && !fired.swap(true, Ordering::SeqCst) {
            let values =
                now(kv.get_many(p, &[keys::outbox_sequence(), keys::outcome_backlog()])).unwrap();
            let mut builder = OutboxBuilder::new(
                values.first().and_then(Option::as_ref),
                values.get(1).and_then(Option::as_ref),
            )
            .unwrap();
            builder.abort_direct(
                "other-rid",
                Terminal::new(codec::ReservationV1::Aborted {
                    repository: REPO.into(),
                    occurred_at_ms: 1,
                    reason: codec::AbortReason::Unspecified,
                    detail: String::new(),
                })
                .unwrap(),
            );
            let mut other = Batch::new();
            builder
                .try_finish(&mut other.preconditions, &mut other.writes)
                .unwrap();
            assert_eq!(now(kv.apply(p, other)).unwrap(), BatchOutcome::Committed);
        }
    };
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)).hook(hook),
        Hooks {
            authorizer: OpenAuthorizer,
            admission: Fixed(AdmissionDecision::allow(Vec::new()).with_reservation("busy-rid")),
            pre_receive: RejectPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        clock,
    );
    let u = upd(HEAD, Missing, A);
    assert_eq!(
        env.update(&Req::update(&key(7), 1, &u, T0), &u)
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(matches!(
        reservation_row(&env, "busy-rid"),
        codec::ReservationV1::Aborted { reason: codec::AbortReason::Unspecified, ref detail, .. }
            if detail == "pre receive refused"
    ));
    assert_eq!(
        codec::decode_backlog(
            &now(env.pipe.meta.get(&ns(), &keys::outcome_backlog()))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .rows,
        2
    );
}

#[test]
fn reserved_replan_exhaustion_from_guard_contention_aborts_internal() {
    let clock = clock();
    let left = AtomicU32::new(MAX_REPLAN + 1);
    let spy = Spy::new(store(&clock)).hook(move |kv, p, batch| {
        // Break the layout guard of each write attempt (not the pending record).
        let layout = keys::layout_version();
        let guarded = batch.preconditions.iter().any(
            |pre| matches!(pre, Precondition::Equals(k, _) | Precondition::Absent(k) if *k == layout),
        );
        if guarded
            && left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
                .is_ok()
        {
            let batch = if now(kv.get(p, &layout)).unwrap().is_some() {
                Batch::new().delete(layout)
            } else {
                Batch::new().put(layout, codec::encode_u32(LAYOUT_VERSION))
            };
            now(kv.apply(p, batch)).unwrap();
        }
    });
    let env = build(
        cfg(authv2()),
        spy,
        with_admission(Fixed(
            AdmissionDecision::allow(Vec::new()).with_reservation("contended-rid"),
        )),
        clock,
    );
    let u = upd(HEAD, Missing, A);
    let err = env
        .update(&Req::update(&key(7), 1, &u, T0), &u)
        .unwrap_err();
    assert_eq!(err.code(), Code::Aborted);
    assert_one_abort(&env, "contended-rid", codec::AbortReason::Internal);
}

#[test]
fn abort_reason_mapping_uses_typed_causes_not_message_text() {
    use codec::AbortReason;
    use reservation::abort_reason;
    // The same words without the marker no longer map to RefConflict.
    assert_eq!(
        abort_reason(&ServerError::aborted_retryable("write contention; retry")).0,
        AbortReason::ReplayRace
    );
    assert_eq!(
        abort_reason(
            &ServerError::aborted_retryable("anything").with_abort_cause(AbortCause::Contention)
        )
        .0,
        AbortReason::Internal
    );
    assert_eq!(
        abort_reason(&plan::epoch_moved()).0,
        AbortReason::EpochMismatch
    );
}

#[test]
fn second_batch_with_a_nonempty_backlog_adds_no_second_delivery_kick() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.outbox_backlog_cap = None;
    let env = build(
        config,
        Spy::new(store(&clock)),
        with_admission(NumberedReservation(AtomicU32::new(0))),
        clock,
    );
    let k = key(7);
    for (n, target) in [(1, A), (2, B)] {
        let u = upd(HEAD, Any, target);
        env.update(&Req::update(&k, n, &u, T0), &u).unwrap();
    }
    let kicks = env
        .batches()
        .iter()
        .flat_map(|batch| &batch.writes)
        .filter(|write| {
            matches!(write, Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind: 8, .. })))
        })
        .count();
    assert_eq!(kicks, 1);
}

#[test]
fn backlog_over_cap_refuses_begin_upload_but_not_reads() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.outbox_backlog_cap = Some(OutboxBacklogCap { rows: 0, bytes: 0 });
    config.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("t".into(), [7; 32])]).unwrap());
    let kv = store(&clock);
    now(kv.apply(
        &ns(),
        Batch::new().put(
            keys::outcome_backlog(),
            codec::encode_backlog(&codec::Backlog { rows: 1, bytes: 1 }),
        ),
    ))
    .unwrap();
    let env = build(
        config,
        Spy::new(kv),
        with_admission(Fixed(AdmissionDecision::allow(Vec::new()))),
        clock,
    );
    let req = Req::signed(&key(7), Procedure::BeginUpload, b"begin", &nonce(1), T0);
    let err = block_on(env.pipe.begin_upload(&env.auth(&req).unwrap(), HEAD, &A, 1)).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unavailable, "outbox backlog; retry")
    );
    assert!(
        err.headers()
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "30")
    );
    // Reads run no admission.
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn duplicate_payment_header_is_denied_only_where_admission_runs() {
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)),
        with_admission(Fixed(AdmissionDecision::allow(Vec::new()))),
        clock,
    );
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let lookup = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let values = |name: &str| {
        if name.eq_ignore_ascii_case("payment-authorization") {
            vec!["one".to_owned(), "two".to_owned()]
        } else {
            lookup(name).into_iter().collect()
        }
    };
    let meta = RequestMeta {
        procedure: req.procedure,
        header: &lookup,
        header_values: Some(&values),
        unary_body: Some(&req.body),
        transport_principal: None,
    };
    // Authentication no longer judges credentials it never forwards.
    let a = env.pipe.authenticate(&meta).unwrap();
    let err = block_on(env.pipe.update_ref(&a, u.clone())).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::PermissionDenied, "admission denied")
    );
    assert!(env.batches().is_empty());
}

#[test]
fn pipeline_refuses_more_extra_credential_headers_than_fit() {
    let clock = clock();
    let mut config = cfg(authv2());
    config.admission_credential_headers = (0..6).map(|i| format!("X-Extra-{i}")).collect();
    let refused = Pipeline::new(
        MemoryBlobStore::default(),
        Spy::new(store(&clock)),
        Hooks::new(),
        config.clone(),
        clock.clone(),
        Arc::new(SpyMetrics::default()),
    );
    assert!(refused.is_err());
    config.admission_credential_headers.truncate(5);
    assert!(
        Pipeline::new(
            MemoryBlobStore::default(),
            Spy::new(store(&clock)),
            Hooks::new(),
            config,
            clock,
            Arc::new(SpyMetrics::default()),
        )
        .is_ok()
    );
}

#[cfg(feature = "published-view")]
#[path = "tests/published.rs"]
mod published_view;
