//! The relay's Worker shape: local source SQL, remote target DO calls.

mod common;

use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys, outbox::OutboxBuilder, tickets::plan_membership};
use mkit_server::timers::{TickBudget, registry::kinds, run_due};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, Key, ManualClock, NamespaceKey, NamespaceStore, RepoId, RepoName,
    Value, Write,
};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::adapter::{ConfigError, timer_registry};
use mkit_server_worker::classes::ShardClass;
use mkit_server_worker::ns_client::DoNamespaceStore;

type Source = SqlKvStore<RusqliteConn>;

#[test]
fn free_plan_caps_lease_sweep_source_subrequests_at_sixteen() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let coordinator_store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let source_client = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
        let ns = NamespaceKey::deployment_default();
        let coordinator = mkit_server::Partition::Coordinator(ns);
        let repo = RepoName::new("sweep").unwrap();
        for n in 0..20 {
            let shard_ref = format!("refs/heads/b{n}");
            let row = codec::LeasedShard {
                epoch: 1,
                expires_at_ms: 100,
                acked_epoch: 1,
                relay_watermark_ms: 0,
                sweep_due_ms: 100,
            };
            coordinator_store
                .apply(
                    &coordinator,
                    Batch::new()
                        .put(
                            keys::leased_shard(&repo, &shard_ref),
                            codec::encode_leased_shard(&row),
                        )
                        .put(
                            keys::timer(
                                100,
                                kinds::LEASE_SWEEP.get(),
                                &mkit_server::timers::lease_sweep::lease_reference(
                                    &repo, &shard_ref,
                                ),
                            ),
                            Value::default(),
                        ),
                )
                .await
                .unwrap();
        }
        let registry = timer_registry(
            ShardClass::NsCoordinator,
            Ok(source_client.clone()),
            Some("free"),
        );
        let report = run_due(
            &coordinator_store,
            &coordinator,
            &registry,
            &ManualClock::new(100),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 16);
        assert_eq!(source_client.transport().calls(), 16);
        assert_eq!(report.deferred, 4);
    });
}

#[test]
#[allow(clippy::too_many_lines)] // One delivery followed by replay shares exact row bytes and call counts.
fn relay_uses_one_watermark_read_and_one_atomic_apply_per_target() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let source = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let target = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("relay").unwrap(),
        };
        let source_partition = D34Shards.ref_shard(&repo, "refs/heads/main");
        let packs = [[0x11; 32], [0x22; 32]];
        let now = 100;
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.relay_at(now);
        let mut batch = Batch::new();
        plan_membership(
            &repo.name,
            &packs,
            &source_partition,
            &D34Shards,
            &repo,
            &mut builder,
            &mut batch.writes,
        );
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        let relay_rows: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| match write {
                Write::Put(key, value)
                    if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))) =>
                {
                    Some((key.clone(), value.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(relay_rows.len(), 2);
        assert_eq!(
            source.apply(&source_partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let registry = timer_registry(ShardClass::RefShard, Ok(target.clone()), Some("free"));
        let clock = ManualClock::new(i64::try_from(now).unwrap());
        let report = run_due(
            &source,
            &source_partition,
            &registry,
            &clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert_eq!(target.transport().calls(), 4, "get rh + apply per target");

        let rh = keys::relay_high_water(&source_partition).unwrap();
        for (key, value) in &relay_rows {
            let Some(keys::ParsedKey::Relay(seq)) = keys::parse(key) else {
                unreachable!();
            };
            let row = codec::decode_relay(value).unwrap();
            assert_eq!(row.at_ms, now);
            assert_eq!(
                target.get(&row.target, &rh).await.unwrap(),
                Some(codec::encode_u64(seq))
            );
            assert_eq!(source.get(&source_partition, key).await.unwrap(), None);
        }
        assert_eq!(target.transport().targets().len(), 2);
        assert!(
            target
                .transport()
                .targets()
                .iter()
                .all(|target| target.binding == ShardClass::RepoIndexShard.binding())
        );
        for pack in &packs {
            let partition = D34Shards.membership(&repo, &BlobKey::pack(*pack));
            let key = keys::membership(&repo.name, pack);
            assert_eq!(
                target.get(&partition, &key).await.unwrap(),
                Some(Value::default())
            );
            // A duplicate must not overwrite a value installed after delivery.
            assert_eq!(
                target
                    .apply(&partition, Batch::new().put(key, Value::new(&b"later"[..])))
                    .await
                    .unwrap(),
                BatchOutcome::Committed
            );
        }

        // Restore the old rows as after a source cleanup failure. The target
        // watermarks make the second fire read-only on both Durable Objects.
        let mut replay =
            Batch::new().put(keys::timer(now, kinds::RELAY.get(), b""), Value::default());
        for (key, value) in relay_rows {
            replay.writes.push(Write::Put(key, value));
        }
        assert_eq!(
            source.apply(&source_partition, replay).await.unwrap(),
            BatchOutcome::Committed
        );
        let before = target.transport().calls();
        let report = run_due(
            &source,
            &source_partition,
            &registry,
            &clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert_eq!(
            target.transport().calls() - before,
            2,
            "only get rh per duplicate target"
        );
        for pack in &packs {
            let partition = D34Shards.membership(&repo, &BlobKey::pack(*pack));
            assert_eq!(
                target
                    .get(&partition, &keys::membership(&repo.name, pack))
                    .await
                    .unwrap(),
                Some(Value::new(&b"later"[..]))
            );
        }
        let (start, end) = keys::class_range(keys::TAG_RELAY);
        assert!(
            source
                .scan(&source_partition, &start, &end, None, 1)
                .await
                .unwrap()
                .entries
                .is_empty()
        );
    });
}

fn source() -> Source {
    SqlKvStore::open(RusqliteConn::open_in_memory().expect("in-memory SQLite"))
        .expect("SQL namespace store")
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("relay").expect("valid repository name"),
    }
}

#[test]
fn relay_is_registered_only_on_ref_shards() {
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
            let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
            let timer = keys::timer(100, kinds::RELAY.get(), b"");
            source
                .apply(
                    &partition,
                    Batch::new().put(timer.clone(), Value::default()),
                )
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
            if class == ShardClass::RefShard {
                assert_eq!(report.fired, 1);
                assert_eq!(source.get(&partition, &timer).await.unwrap(), None);
            } else {
                assert_eq!(report.unknown, 1);
                assert_eq!(
                    source.get(&partition, &timer).await.unwrap(),
                    Some(Value::default())
                );
            }
        }
        assert_eq!(target.transport().calls(), 0);
    });
}

#[test]
fn relay_config_failure_retries_the_stored_timer() {
    block_on(async {
        let source = source();
        let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
        let timer = keys::timer(100, kinds::RELAY.get(), b"");
        source
            .apply(
                &partition,
                Batch::new().put(timer.clone(), Value::default()),
            )
            .await
            .unwrap();
        let target: Result<DoNamespaceStore<Loopback>, _> =
            Err(ConfigError("AUTH_REPOSITORY is not configured".into()));
        let registry = timer_registry(ShardClass::RefShard, target, Some("free"));
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
        assert_eq!(report.failed, 1);
        assert_eq!(report.unknown, 0);
        assert_eq!(report.next_wake_ms, Some(5_100));
        assert_eq!(
            source.get(&partition, &timer).await.unwrap(),
            Some(Value::default())
        );
    });
}

#[test]
fn worker_plan_caps_relay_fires_per_alarm() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let target = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
        for (plan, cap) in [(None, 2), (Some("free"), 2), (Some("paid"), 4)] {
            let source = source();
            let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
            let mut batch = Batch::new();
            for reference in 0..5u8 {
                batch = batch.put(
                    keys::timer(100, kinds::RELAY.get(), &[reference]),
                    Value::default(),
                );
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
            assert_eq!(report.fired, cap);
            assert_eq!(report.deferred, 5 - cap);
        }
        assert_eq!(target.transport().calls(), 0);
    });
}

#[test]
fn worker_relay_defers_chunks_after_two_target_calls_per_fire() {
    block_on(async {
        for plan in ["free", "paid"] {
            let dir = tempfile::tempdir().unwrap();
            let target = Loopback::store(dir.path().to_path_buf(), DoConfig::default());
            let source = source();
            let repo = repo();
            let partition = D34Shards.ref_shard(&repo, "refs/heads/main");
            let destination = D34Shards.membership(&repo, &BlobKey::pack([0x11; 32]));
            let mut batch = Batch::new()
                .put(keys::outbox_sequence(), codec::encode_u64(3))
                .put(keys::timer(100, kinds::RELAY.get(), b""), Value::default());
            for seq in 1..=3u64 {
                let puts = (0..96u8)
                    .map(|key| (Key::new(vec![key]), codec::encode_u64(seq)))
                    .collect();
                let row = codec::RelayV1 {
                    at_ms: 100,
                    target: destination.clone(),
                    puts,
                };
                batch = batch.put(keys::relay(seq), codec::encode_relay(&row).unwrap());
            }
            source.apply(&partition, batch).await.unwrap();
            let registry = timer_registry(ShardClass::RefShard, Ok(target.clone()), Some(plan));
            let mut due = 100;
            for seq in 1..=3u64 {
                let before = target.transport().calls();
                let report = run_due(
                    &source,
                    &partition,
                    &registry,
                    &ManualClock::new(i64::try_from(due).unwrap()),
                    due,
                    &TickBudget::default(),
                )
                .await
                .unwrap();
                assert_eq!(report.fired, 1);
                assert_eq!(
                    target.transport().calls() - before,
                    2,
                    "plan {plan}, seq {seq}"
                );
                assert_eq!(
                    source.get(&partition, &keys::relay(seq)).await.unwrap(),
                    None
                );
                assert_eq!(
                    target.get(&destination, &Key::new(vec![0])).await.unwrap(),
                    Some(codec::encode_u64(seq))
                );
                if seq < 3 {
                    assert!(
                        source
                            .get(&partition, &keys::relay(seq + 1))
                            .await
                            .unwrap()
                            .is_some()
                    );
                    due = report.next_wake_ms.unwrap();
                } else {
                    assert_eq!(report.next_wake_ms, None);
                }
            }
        }
    });
}
