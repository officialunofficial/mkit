//! Native timer persistence, notification, shutdown and server wiring.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use mkit_server::sql::{SqlConn, SqlKvStore};
use mkit_server::store::keys;
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, TimerRegistry};
use mkit_server::{
    Batch, BoxFuture, Clock, Key, NamespaceStore, Partition, StoreError, SystemClock, Value,
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
