//! Paid alarm accounting and colo-local cache invalidation.
// Cache deletion is mounted by wasm glue and exercised by host unit tests.
#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
use mkit_server::purge::{LocalInvalidation, Request, SliceBudget};
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind};
use mkit_server::{BoxFuture, MaybeSend, MaybeSync, NamespaceStore, StoreError};

/// Maximum external operations in one Paid Durable Object alarm.
pub const ALARM_OPERATIONS: u32 = 1000;

/// Launch work reserves headroom for alarm dispatch and response settlement.
/// The project envelope stays 1,000; all launch handlers share the remainder.
pub(crate) const LAUNCH_ALARM_OPERATIONS: u32 = ALARM_OPERATIONS - 40;

/// Reserve a handler's worst-case external calls before any effect.
pub(crate) struct Budgeted<H> {
    pub handler: H,
    pub budget: Option<SliceBudget>,
    pub calls: u32,
}
impl<S: NamespaceStore, H: TimerHandler<S>> TimerHandler<S> for Budgeted<H> {
    fn kind(&self) -> TimerKind {
        self.handler.kind()
    }
    fn max_per_tick(&self) -> Option<u32> {
        self.handler.max_per_tick()
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        if self
            .budget
            .as_ref()
            .is_some_and(|budget| !budget.charge(self.calls))
        {
            Box::pin(async { Ok(Fired::Retry) })
        } else {
            self.handler.fire(ctx, timer)
        }
    }
}

/// One conservative immediate-cache reservation on the outer signed request.
/// The core's shared local/indexed budget still charges each actual operation.
pub(crate) struct RequestLocal {
    pub local: std::sync::Arc<dyn LocalInvalidation>,
    pub budget: mkit_server::indexed::budget::SliceBudget,
    pub reserved: std::sync::atomic::AtomicBool,
}
impl LocalInvalidation for RequestLocal {
    fn invalidate<'a>(
        &'a self,
        request: &'a Request,
        cursor: u32,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async move {
            // Worker callbacks are sequential within this invocation. Mark only
            // successful reservation, before entering even an opaque custom hook.
            if !self.reserved.load(std::sync::atomic::Ordering::SeqCst) {
                self.budget.charge_many(64)?;
                self.reserved
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            self.local.invalidate(request, cursor, budget).await
        })
    }
}

/// Cache API deletion; an absent entry is also successfully invalidated.
pub trait CacheDelete: MaybeSend + MaybeSync {
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>>;
}
/// All currently inserted Worker cache entries plus exact HTTP paths.
#[derive(Debug)]
pub struct LocalCache<C> {
    pub cache: C,
}
impl<C: CacheDelete> LocalInvalidation for LocalCache<C> {
    fn invalidate<'a>(
        &'a self,
        request: &'a Request,
        cursor: u32,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async move {
            request.validate()?;
            let keys = request
                .url_paths
                .iter()
                .map(|path| format!("{}{path}", request.audience))
                .collect::<Vec<_>>();
            for (index, key) in keys.iter().enumerate().skip(cursor as usize) {
                // Deterministic bounded enumeration and delete share one allowance.
                if !budget.charge(2) {
                    return Ok(Some(u32::try_from(index).unwrap_or(u32::MAX)));
                }
                self.cache.delete(key).await?;
            }
            Ok(None)
        })
    }
    fn invalidate_checkpoint<'a>(
        &'a self,
        request: &'a Request,
        checkpoint: &'a [u8],
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            // A restored v0.5.0 namespace position resumes only its path
            // deletion; the catalog walk it tracked no longer exists.
            let cursor = if checkpoint.first() == Some(&b'{') {
                let pos: NamespacePosition = serde_json::from_slice(checkpoint)
                    .map_err(|_| StoreError::Corrupt("invalid purge cursor".into()))?;
                if pos.paths {
                    return Ok(None);
                }
                pos.cursor.to_be_bytes().to_vec()
            } else {
                checkpoint.to_vec()
            };
            let cursor = if cursor.is_empty() {
                0
            } else {
                u32::from_be_bytes(
                    cursor
                        .as_slice()
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("invalid purge cursor".into()))?,
                )
            };
            Ok(self
                .invalidate(request, cursor, budget)
                .await?
                .map(|next| next.to_be_bytes().to_vec()))
        })
    }
}

/// Checkpoint v0.5.0 wrote for a namespace purge that also walked the
/// repository catalog. That walk is gone; `paths` and `cursor` still say how
/// much of the request's own exact-path deletion was done.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespacePosition {
    paths: bool,
    done: bool,
    after: Option<Vec<u8>>,
    repository: Option<String>,
    cursor: u32,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct WorkerCache;
#[cfg(target_arch = "wasm32")]
pub(crate) fn local_cache() -> LocalCache<WorkerCache> {
    LocalCache { cache: WorkerCache }
}
#[cfg(target_arch = "wasm32")]
impl CacheDelete for WorkerCache {
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            worker::Cache::default()
                .delete(key, false)
                .await
                .map_err(|error| {
                    crate::backend_error(mkit_server::storage_error::StorageOp::MetaCall, error)
                })?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::purge::{PurgeDelivery, PurgeSink, Trigger, plan_enqueue, read_request};
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    use mkit_server::{Batch, ManualClock, MemoryKv, NamespaceKey, Partition, RepoName};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    };

    #[derive(Clone, Default)]
    struct Cache(Arc<Mutex<Vec<String>>>);
    impl CacheDelete for Cache {
        fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .expect("cache fixture mutex should be available")
                    .push(key.to_owned());
                Ok(())
            })
        }
    }
    fn request(id: &str) -> Request {
        Request {
            purge_id: id.into(),
            audience: "https://server.example".into(),
            repository: "root/repo".into(),
            namespace: String::new(),
            trigger: Trigger::Suspension,
            url_paths: vec!["/object".into()],
            object_ids: Vec::new(),
            refs: Vec::new(),
        }
    }

    struct HandlerCalls {
        kind: u8,
        calls: u32,
        recorded: Arc<AtomicU32>,
    }

    #[derive(Clone)]
    struct NamespaceSink(Arc<Mutex<Vec<Request>>>);
    impl PurgeSink for NamespaceSink {
        fn deliver<'a>(&'a self, request: &'a Request) -> BoxFuture<'a, Result<(), StoreError>> {
            Box::pin(async move {
                self.0.lock().unwrap().push(request.clone());
                Ok(())
            })
        }
    }

    #[test]
    fn namespace_request_deletes_its_exact_paths_and_nothing_else() {
        let mut work = request("namespace");
        work.repository.clear();
        work.namespace = "root".into();
        work.url_paths = vec!["/object".into(), "/proof".into()];
        let cache = Cache::default();
        let local = LocalCache {
            cache: cache.clone(),
        };
        let first = futures::executor::block_on(local.invalidate_checkpoint(
            &work,
            &[],
            &SliceBudget::new(2),
        ))
        .unwrap();
        assert_eq!(first, Some(1u32.to_be_bytes().to_vec()));
        let done = futures::executor::block_on(local.invalidate_checkpoint(
            &work,
            &first.unwrap(),
            &SliceBudget::new(2),
        ))
        .unwrap();
        assert_eq!(done, None);
        assert_eq!(
            *cache.0.lock().unwrap(),
            [
                "https://server.example/object",
                "https://server.example/proof"
            ]
        );
        work.url_paths.clear();
        let cache = Cache::default();
        let local = LocalCache {
            cache: cache.clone(),
        };
        assert_eq!(
            futures::executor::block_on(local.invalidate_checkpoint(
                &work,
                &[],
                &SliceBudget::new(0)
            ))
            .unwrap(),
            None
        );
        assert!(cache.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn namespace_purge_delivers_once_to_the_sink_and_completes() {
        let store = MemoryKv::default();
        let partition = Partition::Coordinator(NamespaceKey::deployment_default());
        let mut work = request("manual-namespace");
        work.repository.clear();
        work.namespace = "root".into();
        work.trigger = Trigger::Manual;
        work.url_paths.clear();
        store
            .apply(&partition, plan_enqueue(&work, 10, None, None).unwrap())
            .await
            .unwrap();
        let cache = Cache::default();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let registry = TimerRegistry::new().register(PurgeDelivery::new(
            Arc::new(LocalCache {
                cache: cache.clone(),
            }),
            Some(Arc::new(NamespaceSink(delivered.clone()))),
            SliceBudget::new(6),
        ));
        let clock = ManualClock::new(10);
        for tick in 0..4 {
            let now = 10 + tick * 1_000_000;
            clock.set(i64::try_from(now).unwrap());
            run_due(
                &store,
                &partition,
                &registry,
                &clock,
                now,
                &TickBudget::new(1, 1, 16, 1000),
            )
            .await
            .unwrap();
        }
        assert!(
            read_request(&store, &partition, &work.purge_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(*delivered.lock().unwrap(), [work]);
        assert!(cache.0.lock().unwrap().is_empty());
    }
    #[test]
    fn signed_immediate_reservation_is_once_per_invocation_and_refuses_before_custom_effects() {
        futures::executor::block_on(async {
            struct Custom(
                std::sync::Arc<AtomicU32>,
                mkit_server::indexed::budget::SliceBudget,
            );
            impl LocalInvalidation for Custom {
                fn invalidate<'a>(
                    &'a self,
                    _: &'a Request,
                    _: u32,
                    local: &'a SliceBudget,
                ) -> BoxFuture<'a, Result<Option<u32>, StoreError>> {
                    Box::pin(async move {
                        assert!(
                            self.1.used() >= 64,
                            "outer reservation precedes opaque effects"
                        );
                        if local.charge(40) {
                            self.0.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(None)
                    })
                }
            }
            let calls = Arc::new(AtomicU32::new(0));
            let outer = mkit_server::indexed::budget::SliceBudget::new(9000);
            let indexed = mkit_server::indexed::budget::SliceBudget::new(9000);
            let local = SliceBudget::with_parent(64, indexed.clone());
            let wrapper = RequestLocal {
                local: Arc::new(Custom(calls.clone(), outer.clone())),
                budget: outer.clone(),
                reserved: std::sync::atomic::AtomicBool::new(false),
            };
            for action in ["acceptance", "resume"] {
                wrapper
                    .invalidate(&request(action), 0, &local)
                    .await
                    .unwrap();
            }
            assert_eq!(
                (
                    outer.used(),
                    indexed.used(),
                    local.used(),
                    calls.load(Ordering::SeqCst)
                ),
                (64, 40, 40, 1)
            );
            let fresh = RequestLocal {
                local: wrapper.local.clone(),
                budget: outer.clone(),
                reserved: std::sync::atomic::AtomicBool::new(false),
            };
            fresh
                .invalidate(&request("next invocation"), 0, &SliceBudget::new(64))
                .await
                .unwrap();
            assert_eq!((outer.used(), calls.load(Ordering::SeqCst)), (128, 2));
            let spent = mkit_server::indexed::budget::SliceBudget::new(9000);
            spent.charge_many(8937).unwrap();
            let refused = RequestLocal {
                local: wrapper.local.clone(),
                budget: spent.clone(),
                reserved: std::sync::atomic::AtomicBool::new(false),
            };
            for _ in 0..2 {
                assert!(
                    refused
                        .invalidate(&request("refused"), 0, &SliceBudget::new(64))
                        .await
                        .is_err()
                );
                assert!(!refused.reserved.load(Ordering::SeqCst));
            }
            assert_eq!((spent.used(), calls.load(Ordering::SeqCst)), (8937, 2));
        });
    }

    #[test]
    fn ordinary_pipeline_invalidation_reserves_outer_request_before_cache_and_refuses_when_spent() {
        futures::executor::block_on(async {
            use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
            use mkit_server::{Addressing, MemoryBlobStore, NoopMetrics, RepoId};
            for remaining in [64, 63] {
                let outer = mkit_server::indexed::budget::SliceBudget::new(9000);
                outer.charge_many(9000 - remaining).unwrap();
                let cache = Cache::default();
                let wrapper = Arc::new(RequestLocal {
                    local: Arc::new(LocalCache {
                        cache: cache.clone(),
                    }),
                    budget: outer.clone(),
                    reserved: std::sync::atomic::AtomicBool::new(false),
                });
                let repo = RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new("repo").unwrap(),
                };
                let mut cfg = PipelineConfig::new(
                    Addressing::Single { repo: repo.clone() },
                    AuthMode::Open,
                    mkit_server::upload::UploadLimits {
                        max_total_bytes: 1024,
                        max_chunks: 4,
                    },
                );
                cfg.purge = Some(
                    mkit_server::purge::PurgeConfig::new(
                        "https://server.example".into(),
                        true,
                        true,
                    )
                    .with_local(wrapper.clone()),
                );
                let pipeline = Pipeline::new(
                    MemoryBlobStore::default(),
                    MemoryKv::default(),
                    Hooks::new(),
                    cfg,
                    Arc::new(ManualClock::new(10)),
                    Arc::new(NoopMetrics),
                )
                .unwrap();
                pipeline.invalidate_local_cache(&repo).await;
                assert_eq!(wrapper.reserved.load(Ordering::SeqCst), remaining == 64);
                assert_eq!(outer.used(), if remaining == 64 { 9000 } else { 8937 });
                assert!(cache.0.lock().unwrap().is_empty());
            }
        });
    }

    impl<S: NamespaceStore> TimerHandler<S> for HandlerCalls {
        fn kind(&self) -> TimerKind {
            TimerKind::new(self.kind)
        }
        fn fire<'a>(
            &'a self,
            _: &'a TimerCtx<'a, S>,
            _: &'a DueTimer,
        ) -> BoxFuture<'a, Result<Fired, StoreError>> {
            self.recorded.fetch_add(self.calls, Ordering::SeqCst);
            Box::pin(async { Ok(Fired::Done(Batch::new())) })
        }
    }
    struct Sink(Arc<AtomicU32>);
    impl PurgeSink for Sink {
        fn deliver<'a>(&'a self, _: &'a Request) -> BoxFuture<'a, Result<(), StoreError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }
    #[tokio::test]
    async fn sixteen_heads_share_one_whole_alarm_budget_and_keep_unfinished_purges() {
        let store = MemoryKv::default();
        let clock = ManualClock::new(10);
        let budget = SliceBudget::new(LAUNCH_ALARM_OPERATIONS);
        let recorded = Arc::new(AtomicU32::new(0));
        let cache = Cache::default();
        let mut registry = TimerRegistry::new();
        for (kind, calls) in [
            (1, 64),
            (3, 64),
            (7, 256),
            (8, 16),
            (10, 3),
            (4, 1),
            (13, 64),
            (15, 64),
        ] {
            registry = registry.register(Budgeted {
                handler: HandlerCalls {
                    kind,
                    calls,
                    recorded: recorded.clone(),
                },
                budget: Some(budget.clone()),
                calls,
            });
        }
        registry = registry.register(PurgeDelivery::new(
            Arc::new(LocalCache {
                cache: cache.clone(),
            }),
            Some(Arc::new(Sink(recorded.clone()))),
            budget.clone(),
        ));
        let mut partitions = Vec::new();
        for bucket in 0..16 {
            let partition = Partition::RefIndex {
                ns: NamespaceKey::deployment_default(),
                repo: RepoName::new("repo").unwrap(),
                bucket,
            };
            let request = request(&format!("purge:{bucket}"));
            let mut batch = plan_enqueue(&request, 10, None, None).unwrap();
            for kind in [1, 3, 7, 8, 10, 4, 13, 15] {
                batch = batch.put(
                    mkit_server::store::keys::timer(10, kind, b""),
                    mkit_server::Value::default(),
                );
            }
            store.apply(&partition, batch).await.unwrap();
            partitions.push((partition, request.purge_id));
        }
        // This is precisely the NsObject alarm's one-reset/many-head structure.
        budget.reset();
        for (partition, _) in &partitions {
            run_due(
                &store,
                partition,
                &registry,
                &clock,
                10,
                &TickBudget::default(),
            )
            .await
            .unwrap();
        }
        let actual =
            recorded.load(Ordering::SeqCst) + u32::try_from(cache.0.lock().unwrap().len()).unwrap();
        assert!(actual <= budget.used());
        assert!(budget.used() <= LAUNCH_ALARM_OPERATIONS);
        let mut pending = 0;
        for (partition, id) in &partitions {
            pending += u32::from(read_request(&store, partition, id).await.unwrap().is_some());
        }
        assert!(
            pending > 0,
            "exhaustion cannot acknowledge undelivered work"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod v050_tests {
    crate::stored_golden::tests!(purge);
}
