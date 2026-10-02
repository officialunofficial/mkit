//! Native timer persistence, notification, shutdown and server wiring.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use mkit_server::sql::{SqlConn, SqlKvStore};
use mkit_server::store::{codec, keys, tickets};
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, TimerRegistry};
use mkit_server::{
    Batch, BoxFuture, Clock, Key, MemoryBlobStore, NamespaceKey, NamespaceStore, Partition,
    RepoName, StoreError, SystemClock, Value,
};
use mkit_server_native::timers::{TimerDriver, TimerNotifying, TimerStore};
use mkit_server_native::{Blocking, RusqliteConn, Shutdown, server};
use tokio::sync::Notify;

const KIND: TimerKind = TimerKind::new(0xF0);

fn partition() -> Partition {
    Partition::decode(b"ndefault\0").unwrap()
}
fn now() -> u64 {
    u64::try_from(SystemClock.now_ms()).unwrap()
}
fn result_key(reference: &[u8]) -> Key {
    Key::new([&b"r\0done-"[..], reference].concat())
}
fn open(path: &std::path::Path) -> TimerStore {
    Blocking::new(TimerNotifying::new(
        SqlKvStore::open(RusqliteConn::open(path).unwrap()).unwrap(),
    ))
}
async fn put(store: &TimerStore, due: u64, reference: &[u8]) {
    store
        .apply(
            &partition(),
            Batch::new().put(keys::timer(due, KIND.get(), reference), Value::default()),
        )
        .await
        .unwrap();
}
async fn wait_fired(store: &TimerStore, reference: &[u8]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while store
            .get(&partition(), &result_key(reference))
            .await
            .unwrap()
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

struct Complete;
impl<S: NamespaceStore> TimerHandler<S> for Complete {
    fn kind(&self) -> TimerKind {
        KIND
    }
    fn fire<'a>(
        &'a self,
        _ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            Ok(Fired::Done(Batch::new().put(
                result_key(&timer.reference),
                Value::new(&b"done"[..]),
            )))
        })
    }
}

struct Blocked {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
impl<S: NamespaceStore> TimerHandler<S> for Blocked {
    fn kind(&self) -> TimerKind {
        KIND
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            Complete.fire(ctx, timer).await
        })
    }
}

fn driver(store: &TimerStore) -> TimerDriver {
    TimerDriver::new(
        store.clone(),
        TimerRegistry::new().register(Complete),
        Arc::new(SystemClock),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_driver_fires_ticket_expiry() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("expiry.sqlite3"));
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let repo = RepoName::new("repo").unwrap();
    let ref_name = "refs/heads/main".to_owned();
    let rid = "s:2222222222222222222222222222222222222222222222222222222222222222";
    let id = tickets::ticket_id(rid);
    let due = now();
    let ticket = codec::TicketV1 {
        authority_generation: None,
        repo: repo.clone(),
        ref_name: ref_name.clone(),
        signer: [1; 32],
        pack_id: [2; 32],
        bytes: 8 * 1024 * 1024 + 1,
        part_size: 8 * 1024 * 1024,
        expires_at_ms: due,
        created_at_ms: due - 1,
        reservation_id: rid.into(),
        upload_session: None,
    };
    store
        .apply(
            &p,
            Batch::new()
                .put(keys::ticket(&id), codec::encode_ticket(&ticket))
                .put(
                    keys::reservation(rid).unwrap(),
                    codec::encode_reservation(&codec::ReservationV1::Ticketed { ticket_id: id }),
                )
                .put(
                    keys::ticket_index(&repo, &ref_name, &ticket.pack_id, &ticket.signer).unwrap(),
                    codec::encode_ref_id(&id),
                )
                .put(
                    keys::tickets_per_ref(&repo, &ref_name).unwrap(),
                    codec::encode_u64(1),
                )
                .put(
                    keys::tickets_per_signer(&repo, &ref_name, &ticket.signer).unwrap(),
                    codec::encode_u64(1),
                )
                .put(
                    keys::timer(
                        due,
                        mkit_server::timers::registry::kinds::TICKET_EXPIRY.get(),
                        &id,
                    ),
                    Value::default(),
                ),
        )
        .await
        .unwrap();
    let shutdown = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            String::new(),
            mkit_server::pipeline::NoOutcomes,
        ),
        Arc::new(SystemClock),
    )
    .start(shutdown.clone())
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // The Expired outcome is delivered and acknowledged by kind 8 right
            // after expiry, so the closed ticket is the durable evidence.
            if store.get(&p, &keys::ticket(&id)).await.unwrap().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.trigger();
    task.await.unwrap();
}

/// The same expiry on a Multi deployment's namespaced partition: the
/// driver's startup `timer_heads` scan and `TimerNotifying` both key on
/// the partition, which is `Namespace(ed25519-<key>)` — not the default —
/// for a namespaced repository.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_driver_fires_ticket_expiry_on_a_namespaced_partition() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("expiry-multi.sqlite3"));
    let p = Partition::Namespace(NamespaceKey::from_namespace(
        &mkit_core::repo_identity::Namespace::Ed25519([0x5e; 32]),
    ));
    let repo = RepoName::new("repo").unwrap();
    let ref_name = "refs/heads/main".to_owned();
    let rid = "s:3333333333333333333333333333333333333333333333333333333333333333";
    let id = tickets::ticket_id(rid);
    let due = now();
    let ticket = codec::TicketV1 {
        authority_generation: None,
        repo: repo.clone(),
        ref_name: ref_name.clone(),
        signer: [1; 32],
        pack_id: [2; 32],
        bytes: 8 * 1024 * 1024 + 1,
        part_size: 8 * 1024 * 1024,
        expires_at_ms: due,
        created_at_ms: due - 1,
        reservation_id: rid.into(),
        upload_session: None,
    };
    store
        .apply(
            &p,
            Batch::new()
                .put(keys::ticket(&id), codec::encode_ticket(&ticket))
                .put(
                    keys::reservation(rid).unwrap(),
                    codec::encode_reservation(&codec::ReservationV1::Ticketed { ticket_id: id }),
                )
                .put(
                    keys::ticket_index(&repo, &ref_name, &ticket.pack_id, &ticket.signer).unwrap(),
                    codec::encode_ref_id(&id),
                )
                .put(
                    keys::tickets_per_ref(&repo, &ref_name).unwrap(),
                    codec::encode_u64(1),
                )
                .put(
                    keys::tickets_per_signer(&repo, &ref_name, &ticket.signer).unwrap(),
                    codec::encode_u64(1),
                )
                .put(
                    keys::timer(
                        due,
                        mkit_server::timers::registry::kinds::TICKET_EXPIRY.get(),
                        &id,
                    ),
                    Value::default(),
                ),
        )
        .await
        .unwrap();
    let shutdown = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            String::new(),
            mkit_server::pipeline::NoOutcomes,
        ),
        Arc::new(SystemClock),
    )
    .start(shutdown.clone())
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // The Expired outcome is delivered and acknowledged by kind 8
            // right after expiry, so the closed ticket is the durable evidence.
            if store.get(&p, &keys::ticket(&id)).await.unwrap().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.trigger();
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_rebuilds_directory_from_sqlite() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("timers.sqlite3");
    let store = open(&path);
    // This binary's first driver has no owner for the timer. Its row survives
    // shutdown and is recovered by the restarted driver with that handler.
    put(&store, now(), b"restart").await;
    let shutdown = Shutdown::new();
    let first = TimerDriver::new(store.clone(), TimerRegistry::new(), Arc::new(SystemClock))
        .start(shutdown.clone())
        .await
        .unwrap();
    shutdown.trigger();
    first.await.unwrap();
    drop(store);
    let reopened = open(&path);
    let shutdown = Shutdown::new();
    let restarted = driver(&reopened).start(shutdown.clone()).await.unwrap();
    wait_fired(&reopened, b"restart").await;
    shutdown.trigger();
    restarted.await.unwrap();
}

#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_restart_fires_due_timer_from_same_database() {
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let origin = format!("http://{address}");
    let meta = format!("sqlite:{}", common::s(&db));
    let cfg = common::resolve_with(
        &[
            "--listen",
            &address.to_string(),
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let (services, locks) = server::open(&cfg).unwrap().into_parts();
    let shutdown = Shutdown::new();
    let first_cfg = cfg.clone();
    let first_shutdown = shutdown.clone();
    let first =
        tokio::spawn(
            async move { server::serve_services(&first_cfg, services, first_shutdown).await },
        );
    let client =
        mkit_server_conformance::wire::client::Client::new(&origin.parse().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while client
            .post(
                "/grpc.health.v1.Health/Check",
                "application/proto",
                &[],
                Vec::new(),
            )
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let raw = Blocking::new(SqlKvStore::open(RusqliteConn::open(&db).unwrap()).unwrap());
    let ref_key = keys::ref_key(
        &mkit_server::RepoName::new("default").unwrap(),
        "refs/heads/restart",
    );
    // Seed through SQLite directly, as after a restore: the running driver's
    // empty directory receives no notification. Restart must rebuild it.
    raw.apply(
        &partition(),
        Batch::new()
            .put(ref_key.clone(), Value::new(&b"head"[..]))
            .put(
                keys::timer(
                    now(),
                    mkit_server::timers::registry::kinds::TEST.get(),
                    b"default\0refs/heads/restart",
                ),
                Value::default(),
            ),
    )
    .await
    .unwrap();
    shutdown.trigger();
    first.await.unwrap().unwrap();
    drop(locks);
    assert!(raw.get(&partition(), &ref_key).await.unwrap().is_some());
    let (services, locks) = server::open(&cfg).unwrap().into_parts();
    let shutdown = Shutdown::new();
    let second_shutdown = shutdown.clone();
    let second =
        tokio::spawn(async move { server::serve_services(&cfg, services, second_shutdown).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while raw.get(&partition(), &ref_key).await.unwrap().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.trigger();
    second.await.unwrap().unwrap();
    drop(locks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn earlier_put_wakes_sleeping_driver() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("timers.sqlite3"));
    let future_due = now() + 120_000;
    put(&store, future_due, b"future").await;
    let shutdown = Shutdown::new();
    let task = driver(&store).start(shutdown.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    put(&store, now() + 50, b"earlier").await;
    wait_fired(&store, b"earlier").await;
    assert!(
        store
            .get(
                &partition(),
                &keys::timer(future_due, KIND.get(), b"future")
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(&partition(), &result_key(b"future"))
            .await
            .unwrap()
            .is_none()
    );
    shutdown.trigger();
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_current_tick_and_starts_no_next_tick() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("timers.sqlite3"));
    put(&store, now(), b"blocked").await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let registry = TimerRegistry::new().register(Blocked {
        entered: entered.clone(),
        release: release.clone(),
    });
    let shutdown = Shutdown::new();
    let mut task = TimerDriver::new(store.clone(), registry, Arc::new(SystemClock))
        .start(shutdown.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    shutdown.trigger();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut task)
            .await
            .is_err()
    );
    put(&store, now(), b"after-shutdown").await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    wait_fired(&store, b"blocked").await;
    assert!(
        store
            .get(&partition(), &result_key(b"after-shutdown"))
            .await
            .unwrap()
            .is_none()
    );
}

/// Both explicit timer drains and an auth sibling wait for an in-flight native
/// tick. The memory pipeline completes synchronously without the gate, so a
/// single poll detects missing exclusion without a sleep or a timing race.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_timer_drain_waits_for_native_tick_and_auth_sibling_shares_gate() {
    use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig, RequestMeta};
    use mkit_server::upload::UploadLimits;
    use mkit_server::{Addressing, MemoryKv, NoopMetrics, Procedure, RepoId};

    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("gated.sqlite3"));
    put(&store, now(), b"blocked").await;
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let stop = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        TimerRegistry::new().register(Blocked {
            entered: entered.clone(),
            release: release.clone(),
        }),
        Arc::new(SystemClock),
    )
    .with_test_timer_gate(gate.clone())
    .start(stop.clone())
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    assert!(
        gate.try_lock().is_err(),
        "native tick did not hold the gate"
    );

    let pipeline = Pipeline::new(
        MemoryBlobStore::default(),
        Arc::new(MemoryKv::default()),
        Hooks::new(),
        PipelineConfig::new(
            Addressing::Single {
                repo: RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new("default").unwrap(),
                },
            },
            AuthMode::Open,
            UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 8,
            },
        ),
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap()
    .with_test_timer_gate(gate);
    let sibling = pipeline.with_auth(AuthMode::Open).unwrap();
    let request = RequestMeta {
        procedure: Procedure::ListRefs,
        header: &|h| (h == "x-mkit-test-run-timers").then(|| "refs/heads/main".into()),
        header_values: None,
        unary_body: None,
        transport_principal: None,
    };
    let authenticated = pipeline.authenticate(&request).unwrap();
    let sibling_authenticated = sibling.authenticate(&request).unwrap();
    let mut drain = Box::pin(pipeline.list_refs(&authenticated, "refs/heads/"));
    let mut sibling_drain = Box::pin(sibling.list_refs(&sibling_authenticated, "refs/heads/"));
    assert!(futures::poll!(drain.as_mut()).is_pending());
    assert!(futures::poll!(sibling_drain.as_mut()).is_pending());

    let ordinary = pipeline
        .authenticate(&RequestMeta {
            header: &|_| None,
            ..request
        })
        .unwrap();
    let mut listing = Box::pin(pipeline.list_refs(&ordinary, "refs/heads/"));
    assert!(futures::poll!(listing.as_mut()).is_ready());
    stop.trigger();
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        task.await.unwrap();
        assert!(drain.await.unwrap().is_empty());
        assert!(sibling_drain.await.unwrap().is_empty());
    })
    .await
    .unwrap();
    assert!(
        store
            .get(&partition(), &result_key(b"blocked"))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_put_during_tick_survives_directory_update() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("timers.sqlite3"));
    put(&store, now(), b"first").await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let shutdown = Shutdown::new();
    let registry = TimerRegistry::new().register(Blocked {
        entered: entered.clone(),
        release: release.clone(),
    });
    let task = TimerDriver::new(store.clone(), registry, Arc::new(SystemClock))
        .start(shutdown.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    // Behind the tick's already-read page, and outside its future scan.
    put(&store, 0, b"second").await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    release.notify_one();
    wait_fired(&store, b"second").await;
    shutdown.trigger();
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_request_still_notifies_after_commit() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("timers.sqlite3"));
    let shutdown = Shutdown::new();
    let task = driver(&store).start(shutdown.clone()).await.unwrap();
    let conn = store.inner().inner().conn().clone();
    let held = Arc::new(Notify::new());
    let locked = held.clone();
    let (release, wait_release) = std::sync::mpsc::channel();
    let lock_task = tokio::task::spawn_blocking(move || {
        conn.transaction(Box::new(move |_| {
            locked.notify_one();
            wait_release.recv().unwrap();
            Ok(())
        }))
        .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(3), held.notified())
        .await
        .unwrap();
    let submitted = Arc::new(Notify::new());
    let started = submitted.clone();
    let writer = store.clone();
    let request = tokio::spawn(async move {
        let p = partition();
        let mut apply = Box::pin(writer.apply(
            &p,
            Batch::new().put(
                keys::timer(now(), KIND.get(), b"cancelled"),
                Value::default(),
            ),
        ));
        assert!(futures::poll!(&mut apply).is_pending());
        started.notify_one();
        apply.await
    });
    tokio::time::timeout(Duration::from_secs(3), submitted.notified())
        .await
        .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    lock_task.await.unwrap();
    wait_fired(&store, b"cancelled").await;
    shutdown.trigger();
    task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fs_layout_serves_without_starting_timer_driver() {
    let root = common::repo_root();
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            "fs-layout",
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let opened = server::open(&cfg).unwrap();
    assert!(opened.timers.is_none());
    assert!(opened.pressure.is_none());
    let (listener, origin) = common::listener().await;
    let shutdown = Shutdown::new();
    let task = common::spawn_serve(listener, opened.router.clone(), &shutdown);
    let client =
        mkit_server_conformance::wire::client::Client::new(&origin.parse().unwrap()).unwrap();
    let response = client
        .post(
            "/grpc.health.v1.Health/Check",
            "application/proto",
            &[],
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    shutdown.trigger();
    task.await.unwrap().unwrap();
}

struct HotPartition {
    hot: Partition,
    hot_fires: Arc<std::sync::atomic::AtomicU32>,
    cold_saw: Arc<std::sync::atomic::AtomicU32>,
}
impl<S: NamespaceStore> TimerHandler<S> for HotPartition {
    fn kind(&self) -> TimerKind {
        KIND
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            use std::sync::atomic::Ordering;
            if ctx.partition == &self.hot {
                self.hot_fires.fetch_add(1, Ordering::SeqCst);
                let next = if timer.reference.as_ref() == b"hot-a" {
                    &b"hot-b"[..]
                } else {
                    &b"hot-a"[..]
                };
                Ok(Fired::Done(
                    Batch::new().put(keys::timer(0, KIND.get(), next), Value::default()),
                ))
            } else {
                self.cold_saw
                    .store(self.hot_fires.load(Ordering::SeqCst), Ordering::SeqCst);
                Complete.fire(ctx, timer).await
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_due_partition_gets_a_turn_before_an_immediate_timer_repeats() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("timers.sqlite3"));
    let hot = Partition::ContentShard(0);
    let cold = Partition::ContentShard(1);
    for (partition, reference) in [(&hot, &b"hot-a"[..]), (&cold, &b"cold"[..])] {
        assert_eq!(
            store
                .apply(
                    partition,
                    Batch::new().put(keys::timer(0, KIND.get(), reference), Value::default())
                )
                .await
                .unwrap(),
            mkit_server::BatchOutcome::Committed
        );
    }
    let hot_fires = Arc::new(AtomicU32::new(0));
    let cold_saw = Arc::new(AtomicU32::new(0));
    let registry = TimerRegistry::new().register(HotPartition {
        hot,
        hot_fires: hot_fires.clone(),
        cold_saw: cold_saw.clone(),
    });
    let shutdown = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        registry,
        Arc::new(mkit_server::ManualClock::new(100)),
    )
    .start(shutdown.clone())
    .await
    .unwrap();
    let fired = tokio::time::timeout(Duration::from_secs(3), async {
        while store
            .get(&cold, &result_key(b"cold"))
            .await
            .unwrap()
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    shutdown.trigger();
    task.await.unwrap();
    assert!(
        fired.is_ok(),
        "hot partition starved the other due partition"
    );
    assert_eq!(
        cold_saw.load(Ordering::SeqCst),
        1,
        "hot partition ran twice before cold partition"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_driver_delivers_outcomes_and_reconciles_pending_rows() {
    use mkit_server::store::codec::{AbortReason, PendingOp, ReservationV1};
    use mkit_server::store::outbox::{OutboxBuilder, Terminal};
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("outcomes.sqlite3"));
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let due = now();
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.abort_direct(
        "done-rid",
        Terminal::new(ReservationV1::Aborted {
            repository: "repo".into(),
            occurred_at_ms: due,
            reason: AbortReason::Unspecified,
            detail: String::new(),
        })
        .unwrap(),
    );
    builder.pending(
        "stale-rid",
        None,
        &ReservationV1::Pending {
            repository: "repo".into(),
            created_at_ms: 1,
            reconcile_at_ms: due,
            op: PendingOp::Write,
        },
    );
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    store.apply(&p, batch).await.unwrap();
    let shutdown = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            "https://server.example".into(),
            mkit_server::pipeline::NoOutcomes,
        ),
        Arc::new(SystemClock),
    )
    .start(shutdown.clone())
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let done = store
                .get(&p, &keys::reservation("done-rid").unwrap())
                .await
                .unwrap()
                .is_none();
            let stale = store
                .get(&p, &keys::reservation("stale-rid").unwrap())
                .await
                .unwrap()
                .is_none();
            if done && stale {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.trigger();
    task.await.unwrap();
}

/// A sink for the drain tests: records every outcome, or never answers.
#[derive(Clone, Default)]
struct Sink {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    hang: bool,
}
impl mkit_server::pipeline::OutcomeSink for Sink {
    async fn deliver(
        &self,
        outcome: &mkit_server::pipeline::Outcome,
    ) -> Result<(), mkit_server::pipeline::DeliveryError> {
        self.seen
            .lock()
            .unwrap()
            .push(outcome.reservation_id.clone());
        if self.hang {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}

async fn seed_outcomes(store: &TimerStore, rids: &[&str]) {
    seed_outcomes_in(
        store,
        &Partition::Namespace(NamespaceKey::deployment_default()),
        rids,
    )
    .await;
}

async fn seed_outcomes_in(store: &TimerStore, p: &Partition, rids: &[&str]) {
    use mkit_server::store::codec::{AbortReason, ReservationV1};
    use mkit_server::store::outbox::{OutboxBuilder, Terminal};
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    for rid in rids {
        builder.abort_direct(
            rid,
            Terminal::new(ReservationV1::Aborted {
                repository: "repo".into(),
                occurred_at_ms: now(),
                reason: AbortReason::Unspecified,
                detail: String::new(),
            })
            .unwrap(),
        );
    }
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    store.apply(p, batch).await.unwrap();
}

fn sink_driver(store: &TimerStore, sink: Sink) -> TimerDriver {
    TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            String::new(),
            sink,
        ),
        Arc::new(SystemClock),
    )
}

/// Outcomes due when the driver is told to stop are delivered before it
/// exits: the driver's stop switch is already on, so the loop never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drain_delivers_due_outcomes_before_exit() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("drain.sqlite3"));
    seed_outcomes(&store, &["one", "two"]).await;
    let sink = Sink::default();
    let stop = Shutdown::new();
    stop.trigger();
    sink_driver(&store, sink.clone())
        .start_with_drain(stop, Duration::from_secs(5))
        .await
        .unwrap()
        .await
        .unwrap();
    assert_eq!(sink.seen.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_drain_due_outcomes_are_left_for_the_next_start() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("nodrain.sqlite3"));
    seed_outcomes(&store, &["one"]).await;
    let sink = Sink::default();
    let stop = Shutdown::new();
    stop.trigger();
    sink_driver(&store, sink.clone())
        .start_with_drain(stop, Duration::ZERO)
        .await
        .unwrap()
        .await
        .unwrap();
    assert!(sink.seen.lock().unwrap().is_empty());
}

/// A sink that never answers cannot hold shutdown past the drain deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drain_deadline_is_respected_when_the_sink_hangs() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("hang.sqlite3"));
    seed_outcomes(&store, &["one"]).await;
    let sink = Sink {
        hang: true,
        ..Sink::default()
    };
    let stop = Shutdown::new();
    stop.trigger();
    let started = std::time::Instant::now();
    sink_driver(&store, sink.clone())
        .start_with_drain(stop, Duration::from_millis(300))
        .await
        .unwrap()
        .await
        .unwrap();
    // Cut by the drain deadline, well before the 5 s per-call sink timeout.
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(sink.seen.lock().unwrap().len(), 1);
}

/// A real sink needs the timer driver, which fs-layout metadata lacks.
#[test]
fn a_real_sink_with_fs_layout_is_a_config_error() {
    let root = common::repo_root();
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let err =
        server::open_with_sink(&cfg, Sink::default(), server::SinkOptions::default()).unwrap_err();
    assert_eq!(err.code, mkit_server_native::exit::CONFIG_ERROR);
    assert!(err.message.contains("fs-layout"), "{}", err.message);
    // The local sink still opens.
    drop(server::open(&cfg).unwrap());
}

/// A sink whose first call blocks until released; every call is recorded.
#[derive(Clone, Default)]
struct GateSink {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    first: Arc<std::sync::atomic::AtomicBool>,
}
impl mkit_server::pipeline::OutcomeSink for GateSink {
    async fn deliver(
        &self,
        outcome: &mkit_server::pipeline::Outcome,
    ) -> Result<(), mkit_server::pipeline::DeliveryError> {
        self.seen
            .lock()
            .unwrap()
            .push(outcome.reservation_id.clone());
        if !self.first.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(())
    }
}

/// Stop during a pass with three partitions claimed: the two not yet run go
/// back to due-now, and the drain delivers them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_during_a_pass_returns_the_unrun_claims_to_the_drain() {
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("claims.sqlite3"));
    for (index, name) in [&b"nalpha\0"[..], b"nbravo\0", b"ncharlie\0"]
        .into_iter()
        .enumerate()
    {
        let p = Partition::decode(name).unwrap();
        seed_outcomes_in(&store, &p, &[&format!("rid-{index}")]).await;
    }
    let sink = GateSink::default();
    let stop = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            String::new(),
            sink.clone(),
        ),
        Arc::new(SystemClock),
    )
    .start_with_drain(stop.clone(), Duration::from_secs(5))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), sink.entered.notified())
        .await
        .unwrap();
    stop.trigger();
    sink.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sink.seen.lock().unwrap().len(), 3);
}

/// A sink that is slow but succeeds cannot hold shutdown past the drain
/// deadline: it covers the pass already in flight when stop triggers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_deadline_covers_the_in_flight_pass() {
    #[derive(Clone, Default)]
    struct Slow(Arc<std::sync::atomic::AtomicUsize>);
    impl mkit_server::pipeline::OutcomeSink for Slow {
        async fn deliver(
            &self,
            _: &mkit_server::pipeline::Outcome,
        ) -> Result<(), mkit_server::pipeline::DeliveryError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = open(&root.path().join("slow.sqlite3"));
    let rids: Vec<String> = (0..16).map(|i| format!("r{i:02}")).collect();
    let refs: Vec<&str> = rids.iter().map(String::as_str).collect();
    seed_outcomes(&store, &refs).await;
    let calls = Slow::default();
    let stop = Shutdown::new();
    let task = TimerDriver::new(
        store.clone(),
        server::sqlite_timer_registry(
            MemoryBlobStore::default(),
            store.clone(),
            String::new(),
            calls.clone(),
        ),
        Arc::new(SystemClock),
    )
    .start_with_drain(stop.clone(), Duration::from_millis(700))
    .await
    .unwrap();
    while calls.0.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let started = std::time::Instant::now();
    stop.trigger();
    task.await.unwrap();
    // The full fire needs about 4.8 s; the deadline cut it near 0.7 s.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(calls.0.load(std::sync::atomic::Ordering::SeqCst) < 16);
}

/// Through `open_with_sink` and `serve_services`: an outcome committed while
/// the listener drains (a request still in flight) is delivered before
/// `serve_services` returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outcome_committed_during_listener_drain_is_delivered_before_exit() {
    use bytes::Bytes;
    use futures::StreamExt as _;
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let meta = format!("sqlite:{}", common::s(&db));
    let cfg = common::resolve_with(
        &[
            "--listen",
            &address.to_string(),
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let sink = Sink::default();
    let opened =
        server::open_with_sink(&cfg, sink.clone(), server::SinkOptions::default()).unwrap();
    let store = opened.timers.as_ref().unwrap().store().clone();
    let (services, locks) = opened.into_parts();
    let shutdown = Shutdown::new();
    let served = {
        let cfg = cfg.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { server::serve_services(&cfg, services, shutdown).await })
    };
    let stream = loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => break stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    };
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    // A request that stays in flight until its body ends.
    let (tx, rx) = futures::channel::mpsc::unbounded::<Bytes>();
    let body = http_body_util::StreamBody::new(
        rx.map(|b| Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(b))),
    );
    let request = http::Request::post("/grpc.health.v1.Health/Check")
        .header("host", address.to_string())
        .header("content-type", "application/proto")
        .body(body)
        .unwrap();
    let response = tokio::spawn(sender.send_request(request));
    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.trigger();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The listener is draining; this request's commit still lands.
    seed_outcomes(&store, &["late"]).await;
    drop(tx);
    let _ = response.await;
    tokio::time::timeout(Duration::from_secs(15), served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(*sink.seen.lock().unwrap(), ["late"]);
    drop(locks);
}
