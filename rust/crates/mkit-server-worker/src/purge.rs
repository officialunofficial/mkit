//! Paid alarm accounting and colo-local cache invalidation.
use mkit_server::purge::{LocalInvalidation, Request, SliceBudget};
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind};
use mkit_server::{BoxFuture, MaybeSend, MaybeSync, NamespaceStore, StoreError};

/// Maximum external operations in one Paid Durable Object alarm.
pub const ALARM_OPERATIONS: u32 = 1000;

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

/// Cache API deletion; an absent entry is also successfully invalidated.
pub trait CacheDelete: MaybeSend + MaybeSync {
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>>;
}
/// All currently inserted Worker cache entries plus exact HTTP paths.
#[derive(Debug)]
pub struct LocalCache<C> {
    pub cache: C,
    pub snapshot_deployment: Option<String>,
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
            // This lane's automatic API accepts repository intents only.
            if request.repository.is_empty() {
                return Err(StoreError::Invalid(
                    "namespace purge needs repository intents".into(),
                ));
            }
            #[allow(unused_mut)] // Snapshot keys are appended only with published-view enabled.
            let mut keys = request
                .url_paths
                .iter()
                .map(|path| format!("{}{path}", request.audience))
                .collect::<Vec<_>>();
            #[cfg(feature = "published-view")]
            if let Some(deployment) = &self.snapshot_deployment {
                let (namespace, repo) = request
                    .repository
                    .rsplit_once('/')
                    .ok_or_else(|| StoreError::Invalid("invalid repository".into()))?;
                for bucket in 0..16 {
                    keys.push(crate::published_view::cache_key(
                        deployment,
                        &mkit_server::Partition::RefIndex {
                            ns: if namespace == "root" {
                                mkit_server::NamespaceKey::deployment_default()
                            } else {
                                mkit_server::NamespaceKey::from_namespace(
                                    &mkit_core::repo_identity::Namespace::parse(namespace)
                                        .map_err(|_| {
                                            StoreError::Invalid("invalid namespace".into())
                                        })?,
                                )
                            },
                            repo: mkit_server::RepoName::new(repo)
                                .map_err(|_| StoreError::Invalid("invalid repository".into()))?,
                            bucket,
                        },
                    )?);
                }
            }
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
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct WorkerCache;
#[cfg(target_arch = "wasm32")]
pub(crate) fn local_cache(config: &crate::adapter::WorkerConfig) -> LocalCache<WorkerCache> {
    LocalCache {
        cache: WorkerCache,
        snapshot_deployment: {
            #[cfg(feature = "published-view")]
            {
                config
                    .published_view
                    .as_ref()
                    .map(|config| config.deployment.clone())
            }
            #[cfg(not(feature = "published-view"))]
            {
                let _ = config;
                None
            }
        },
    }
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

    #[test]
    #[cfg(feature = "published-view")]
    fn every_repository_selector_deletes_all_snapshot_buckets_and_resumes_at_next_key() {
        use futures::executor::block_on;
        for variant in 0..4 {
            let mut request = request("selectors");
            if variant != 0 {
                request.url_paths.clear();
            }
            if variant == 1 {
                request
                    .object_ids
                    .push("BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
            }
            if variant == 2 {
                request.refs.push("refs/heads/main".into());
            }
            let cache = Cache::default();
            let invalidator = LocalCache {
                cache: cache.clone(),
                snapshot_deployment: Some("deployment".into()),
            };
            let mut cursor = 0;
            loop {
                let budget = SliceBudget::new(6);
                let next = block_on(invalidator.invalidate(&request, cursor, &budget)).unwrap();
                assert!(budget.used() <= 6);
                let Some(next) = next else { break };
                assert!(next > cursor);
                cursor = next;
            }
            let keys = cache.0.lock().unwrap();
            assert_eq!(keys.len(), if variant == 0 { 17 } else { 16 });
            for bucket in 0..16 {
                let key = crate::published_view::cache_key(
                    "deployment",
                    &Partition::RefIndex {
                        ns: NamespaceKey::deployment_default(),
                        repo: RepoName::new("repo").unwrap(),
                        bucket,
                    },
                )
                .unwrap();
                assert_eq!(keys.iter().filter(|k| **k == key).count(), 1);
            }
            if variant == 0 {
                assert!(keys.contains(&"https://server.example/object".into()));
            }
        }
    }

    #[test]
    fn namespace_local_delivery_stays_pending_without_a_repository_intent() {
        let mut request = request("namespace");
        request.repository.clear();
        request.namespace = "root".into();
        let invalidator = LocalCache {
            cache: Cache::default(),
            snapshot_deployment: None,
        };
        assert!(
            futures::executor::block_on(invalidator.invalidate(
                &request,
                0,
                &SliceBudget::new(1000)
            ))
            .is_err()
        );
    }

    #[cfg(feature = "published-view")]
    fn remote_snapshot_keys(request: &Request) -> std::collections::BTreeSet<String> {
        use std::collections::BTreeMap;
        // A real signed sink needs this explicit deployment mapping and its
        // namespace repository registry; neither value travels in CachePurge.
        let deployments = BTreeMap::from([("https://server.example", "fixture-deployment")]);
        let deployment = deployments[request.audience.as_str()];
        let names = if request.repository.is_empty() {
            assert_eq!(request.namespace, "root");
            vec!["repo", "other"]
        } else {
            vec![request.repository.rsplit_once('/').unwrap().1]
        };
        names
            .into_iter()
            .flat_map(|name| {
                (0..16).map(move |bucket| {
                    crate::published_view::cache_key(
                        deployment,
                        &Partition::RefIndex {
                            ns: NamespaceKey::deployment_default(),
                            repo: RepoName::new(name).unwrap(),
                            bucket,
                        },
                    )
                    .unwrap()
                })
            })
            .collect()
    }

    #[test]
    #[cfg(feature = "published-view")]
    fn remote_snapshot_mapping_agrees_with_local_repository_keys_and_namespace_expansion() {
        use futures::executor::block_on;
        use std::collections::BTreeSet;
        for selector in 0..4 {
            let mut request = request("mapping");
            request.url_paths.clear();
            if selector == 1 {
                request
                    .object_ids
                    .push("BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
            }
            if selector == 2 {
                request.refs.push("refs/heads/main".into());
            }
            if selector == 3 {
                request.url_paths.push("/proof".into());
            }
            let cache = Cache::default();
            let invalidator = LocalCache {
                cache: cache.clone(),
                snapshot_deployment: Some("fixture-deployment".into()),
            };
            assert!(
                block_on(invalidator.invalidate(&request, 0, &SliceBudget::new(100)))
                    .unwrap()
                    .is_none()
            );
            let actual = cache
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|key| key.starts_with("https://mkit-snapshot.invalid/"))
                .cloned()
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, remote_snapshot_keys(&request));
            if selector != 0 {
                assert!(request.tags().contains(&mkit_server::purge::cache_tag(
                    &request.audience,
                    "proof",
                    "root/repo"
                )));
                assert!(request.tags().contains(&mkit_server::purge::cache_tag(
                    &request.audience,
                    "snapshot",
                    "root/repo"
                )));
            }
        }
        let mut namespace = request("namespace-mapping");
        namespace.repository.clear();
        namespace.namespace = "root".into();
        namespace.url_paths.clear();
        let cache = Cache::default();
        let invalidator = LocalCache {
            cache: cache.clone(),
            snapshot_deployment: Some("fixture-deployment".into()),
        };
        for name in ["repo", "other"] {
            let mut repository = namespace.clone();
            repository.namespace.clear();
            repository.repository = format!("root/{name}");
            assert!(
                block_on(invalidator.invalidate(&repository, 0, &SliceBudget::new(100)))
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            cache
                .0
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            remote_snapshot_keys(&namespace)
        );
        assert_eq!(
            namespace.tags(),
            [mkit_server::purge::cache_tag(
                &namespace.audience,
                "namespace",
                "root"
            )]
        );
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

    #[tokio::test]
    #[cfg(feature = "published-view")]
    async fn manual_namespace_purge_enumerates_registered_repositories_across_cold_slices() {
        use mkit_server::store::{codec, keys};
        use std::collections::BTreeSet;
        let store = Arc::new(MemoryKv::default());
        let partition = Partition::Coordinator(NamespaceKey::deployment_default());
        for name in ["repo", "other"] {
            store
                .apply(
                    &partition,
                    Batch::new().put(
                        keys::repo_record(&RepoName::new(name).unwrap()),
                        codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
                    ),
                )
                .await
                .unwrap();
        }
        let mut work = request("manual-namespace");
        work.repository.clear();
        work.namespace = "root".into();
        work.trigger = Trigger::Manual;
        work.url_paths = vec!["/object".into(), "/proof".into()];
        store
            .apply(&partition, plan_enqueue(&work, 10, None, None).unwrap())
            .await
            .unwrap();
        let cache = Cache::default();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let clock = ManualClock::new(10);
        for tick in 0..80 {
            let now = 10 + tick * 1_000_000;
            clock.set(i64::try_from(now).unwrap());
            let budget = SliceBudget::new(6);
            let registry = TimerRegistry::new().register(PurgeDelivery::new(
                Arc::new(LocalCache {
                    cache: cache.clone(),
                    snapshot_deployment: Some("fixture-deployment".into()),
                }),
                Some(Arc::new(NamespaceSink(delivered.clone()))),
                budget.clone(),
            ));
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
            assert!(
                budget.used() <= 6,
                "catalog reads and cache deletes share the slice allowance"
            );
            if read_request(&store, &partition, &work.purge_id)
                .await
                .unwrap()
                .is_none()
            {
                break;
            }
        }
        assert!(
            read_request(&store, &partition, &work.purge_id)
                .await
                .unwrap()
                .is_none(),
            "a finite namespace catalog must complete after bounded cold slices"
        );
        let mut expected = remote_snapshot_keys(&work);
        expected.extend(
            work.url_paths
                .iter()
                .map(|path| format!("{}{path}", work.audience)),
        );
        assert_eq!(
            cache
                .0
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(*delivered.lock().unwrap(), [work]);
        assert!(
            store
                .get(&partition, &keys::outcome_backlog())
                .await
                .unwrap()
                .is_none()
        );
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
        let budget = SliceBudget::new(ALARM_OPERATIONS);
        let recorded = Arc::new(AtomicU32::new(0));
        let cache = Cache::default();
        let mut registry = TimerRegistry::new();
        for (kind, calls) in [(3, 64), (7, 256), (8, 16), (10, 3), (4, 1)] {
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
                snapshot_deployment: None,
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
            for kind in [3, 7, 8, 10, 4] {
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
        assert!(budget.used() <= ALARM_OPERATIONS);
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
