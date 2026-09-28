//! The relay's Worker shape: local source SQL, remote target DO calls.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys, outbox::OutboxBuilder, tickets::plan_membership};
use mkit_server::timers::{
    DueTimer, Fired, TickBudget, TimerCtx, TimerHandler, TimerKind, TimerRegistry, registry::kinds,
    run_due,
};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BoxFuture, ManualClock, NamespaceKey, NamespaceStore, RepoId,
    RepoName, StoreError, Value, Write,
};
use mkit_server_native::RusqliteConn;
use mkit_server_worker::ns_client::DoNamespaceStore;

type Source = SqlKvStore<RusqliteConn>;

// The timer context and row are non-exhaustive. Let run_due construct them,
// then explicitly invoke fire across the two different concrete store types.
struct WorkerRelay {
    relay: RelayHandler<DoNamespaceStore<Loopback>>,
    fires: Arc<AtomicUsize>,
}

impl TimerHandler<Source> for WorkerRelay {
    fn kind(&self) -> TimerKind {
        kinds::RELAY
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, Source>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            self.fires.fetch_add(1, Ordering::SeqCst);
            self.relay.fire(ctx, timer).await
        })
    }
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
        let fires = Arc::new(AtomicUsize::new(0));
        let registry = TimerRegistry::new().register(WorkerRelay {
            relay: RelayHandler {
                target: target.clone(),
                hook: NoHook,
                budget: RelayBudget::default(),
            },
            fires: fires.clone(),
        });
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
        assert_eq!(fires.load(Ordering::SeqCst), 1);
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
        assert_eq!(fires.load(Ordering::SeqCst), 2);
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
