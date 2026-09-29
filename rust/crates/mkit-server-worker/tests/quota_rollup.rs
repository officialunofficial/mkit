//! Kind-5 namespace quota rollups on the Worker's Durable Object classes
//! (WP-1.26b): registered where `qs`/`qc` rows live, unknown elsewhere,
//! retained on a configuration error and capped per alarm tick.

mod common;

use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys};
use mkit_server::timers::{TickBudget, registry::kinds, run_due};
use mkit_server::{
    Batch, ManualClock, NamespaceKey, NamespaceStore, Partition, RepoId, RepoName, Value,
};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::adapter::{ConfigError, timer_registry};
use mkit_server_worker::classes::ShardClass;
use mkit_server_worker::ns_client::DoNamespaceStore;

type Source = SqlKvStore<RusqliteConn>;

fn source() -> Source {
    SqlKvStore::open(RusqliteConn::open_in_memory().expect("in-memory SQLite"))
        .expect("SQL namespace store")
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("rollup").expect("valid repository name"),
    }
}

/// The partition a class's rollup timers live on.
fn partition(class: ShardClass) -> Partition {
    let ns = NamespaceKey::deployment_default();
    match class {
        ShardClass::RefShard => D34Shards.ref_shard(&repo(), "refs/heads/main"),
        ShardClass::NsCoordinator => Partition::Coordinator(ns),
        _ => Partition::Namespace(ns),
    }
}

/// A live-window rollup timer for `window`, due at 100.
fn timer(window: u64) -> (mkit_server::Key, Value) {
    (
        keys::timer(100, kinds::QUOTA_ROLLUP.get(), &window.to_be_bytes()),
        codec::encode_u64(3_600_000),
    )
}

#[test]
fn rollup_is_registered_on_the_classes_that_hold_quota_rows_only() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let target = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
        for class in [
            ShardClass::RefStore,
            ShardClass::NsCoordinator,
            ShardClass::RefShard,
            ShardClass::RepoIndexShard,
            ShardClass::ContentIndexShard,
        ] {
            let source = source();
            let partition = partition(class);
            let (key, value) = timer(7);
            source
                .apply(&partition, Batch::new().put(key.clone(), value.clone()))
                .await
                .unwrap();
            let registry = timer_registry(class, Ok(target.clone()), None);
            let report = run_due(
                &source,
                &partition,
                &registry,
                &ManualClock::new(100),
                100,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            if matches!(
                class,
                ShardClass::RefStore | ShardClass::NsCoordinator | ShardClass::RefShard
            ) {
                assert_eq!(report.fired, 1, "{class:?}");
                assert_eq!(report.unknown, 0, "{class:?}");
            } else {
                assert_eq!(report.unknown, 1, "{class:?}");
                assert_eq!(
                    source.get(&partition, &key).await.unwrap(),
                    Some(value),
                    "{class:?} must keep the row it cannot fire"
                );
            }
        }
    });
}

#[test]
fn rollup_config_failure_retries_the_stored_timer() {
    block_on(async {
        for class in [
            ShardClass::RefStore,
            ShardClass::NsCoordinator,
            ShardClass::RefShard,
        ] {
            let source = source();
            let partition = partition(class);
            let (key, value) = timer(7);
            source
                .apply(&partition, Batch::new().put(key.clone(), value.clone()))
                .await
                .unwrap();
            let target: Result<DoNamespaceStore<Loopback>, _> =
                Err(ConfigError("AUTH_REPOSITORY is not configured".into()));
            let registry = timer_registry(class, target, Some("free"));
            let report = run_due(
                &source,
                &partition,
                &registry,
                &ManualClock::new(100),
                100,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            // Retained with backoff, not dropped and not "unknown".
            assert_eq!(report.failed, 1, "{class:?}");
            assert_eq!(report.unknown, 0, "{class:?}");
            assert_eq!(
                source.get(&partition, &key).await.unwrap(),
                Some(value),
                "{class:?}"
            );
        }
    });
}

#[test]
fn rollup_fires_are_capped_at_four_per_alarm_on_every_plan() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let target = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
        for plan in [None, Some("free"), Some("paid")] {
            let source = source();
            let partition = partition(ShardClass::RefShard);
            let mut batch = Batch::new();
            for window in 0..9u64 {
                let (key, value) = timer(window);
                batch = batch.put(key, value);
            }
            source.apply(&partition, batch).await.unwrap();
            let registry = timer_registry(ShardClass::RefShard, Ok(target.clone()), plan);
            let report = run_due(
                &source,
                &partition,
                &registry,
                &ManualClock::new(100),
                100,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!(report.fired, 4, "plan {plan:?}");
            assert_eq!(report.deferred, 5, "plan {plan:?}");
        }
    });
}
