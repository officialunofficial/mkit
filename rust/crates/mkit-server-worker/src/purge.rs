//! Paid alarm accounting and colo-local cache invalidation.
// Namespace delivery is mounted by wasm glue and exercised by host unit tests.
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

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespacePosition {
    paths: bool,
    done: bool,
    after: Option<Vec<u8>>,
    repository: Option<String>,
    cursor: u32,
}
fn bad_position() -> StoreError {
    StoreError::Corrupt("invalid namespace purge checkpoint".into())
}
struct NamespaceCache<'a, S, T, C> {
    local: &'a LocalCache<C>,
    source: &'a S,
    remote: &'a T,
    partition: &'a mkit_server::Partition,
    sharding: mkit_server::pipeline::Sharding,
    single: Option<&'a mkit_server::RepoId>,
}
impl<S: NamespaceStore, T: NamespaceStore, C: CacheDelete> LocalInvalidation
    for NamespaceCache<'_, S, T, C>
{
    fn invalidate<'a>(
        &'a self,
        request: &'a Request,
        cursor: u32,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<u32>, StoreError>> {
        self.local.invalidate(request, cursor, budget)
    }
    #[allow(clippy::too_many_lines)] // One checkpoint machine owns catalog traversal and cache deletion.
    fn invalidate_checkpoint<'a>(
        &'a self,
        request: &'a Request,
        checkpoint: &'a [u8],
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            if !request.repository.is_empty() {
                return self
                    .local
                    .invalidate_checkpoint(request, checkpoint, budget)
                    .await;
            }
            request.validate()?;
            let namespace = if request.namespace == "root" {
                mkit_server::NamespaceKey::deployment_default()
            } else {
                mkit_server::NamespaceKey::from_namespace(
                    &mkit_core::repo_identity::Namespace::parse(&request.namespace)
                        .map_err(|_| bad_position())?,
                )
            };
            let target = match self.sharding {
                mkit_server::pipeline::Sharding::Single => {
                    mkit_server::Partition::Namespace(namespace.clone())
                }
                _ => mkit_server::Partition::Coordinator(namespace.clone()),
            };
            let mut pos: NamespacePosition = if checkpoint.is_empty() {
                NamespacePosition::default()
            } else {
                serde_json::from_slice(checkpoint).map_err(|_| bad_position())?
            };
            if checkpoint.len() > 4096
                || pos.after.as_ref().is_some_and(Vec::is_empty)
                || (pos.done && pos.after.is_some())
                || (pos.done && pos.repository.is_none())
                || (pos.paths && pos.repository.is_none() && pos.cursor != 0)
                || pos
                    .repository
                    .as_ref()
                    .is_some_and(|name| mkit_server::RepoName::new(name).is_err())
                || pos.cursor as usize
                    > if pos.paths {
                        16
                    } else {
                        request.url_paths.len()
                    }
            {
                return Err(bad_position());
            }
            loop {
                if !pos.paths {
                    while let Some(path) = request.url_paths.get(pos.cursor as usize) {
                        if !budget.charge(2) {
                            break;
                        }
                        self.local
                            .cache
                            .delete(&format!("{}{path}", request.audience))
                            .await?;
                        pos.cursor += 1;
                    }
                    if pos.cursor as usize != request.url_paths.len() {
                        break;
                    }
                    pos.paths = true;
                    pos.cursor = 0;
                }
                if let Some(repository) = &pos.repository {
                    let mut child = request.clone();
                    child.namespace.clear();
                    child.repository = format!("{}/{}", request.namespace, repository);
                    child.url_paths.clear();
                    if let Some(cursor) = self.local.invalidate(&child, pos.cursor, budget).await? {
                        pos.cursor = cursor;
                        break;
                    }
                    pos.repository = None;
                    pos.cursor = 0;
                }
                if pos.done {
                    return Ok(None);
                }
                if let Some(single) = self.single {
                    pos.done = true;
                    if single.namespace == namespace {
                        pos.repository = Some(single.name.as_str().to_owned());
                    }
                    continue;
                }
                if !budget.charge(1) {
                    break;
                }
                let after = pos
                    .after
                    .as_ref()
                    .map(|c| mkit_server::Cursor::new(c.clone()));
                let start = mkit_server::Key::new(b"rr\0".to_vec());
                let end = mkit_server::Key::new(b"rr\x01".to_vec());
                let page = if target == *self.partition {
                    self.source
                        .scan(&target, &start, &end, after.as_ref(), 1)
                        .await?
                } else {
                    self.remote
                        .scan(&target, &start, &end, after.as_ref(), 1)
                        .await?
                };
                if page.entries.len() > 1 || (page.entries.is_empty() && page.next.is_some()) {
                    return Err(bad_position());
                }
                pos.done = page.next.is_none();
                pos.after = page.next.map(|c| c.as_bytes().to_vec());
                if let Some((key, value)) = page.entries.first() {
                    let Some(mkit_server::store::keys::ParsedKey::RepoRecord(repo)) =
                        mkit_server::store::keys::parse(key)
                    else {
                        return Err(bad_position());
                    };
                    mkit_server::store::codec::decode_repo_record(value)?;
                    pos.repository = Some(repo.as_str().to_owned());
                }
            }
            Ok(Some(serde_json::to_vec(&pos).map_err(|_| bad_position())?))
        })
    }
}
/// Kind-11 delivery with durable catalog traversal and context-local reads.
pub(crate) struct NamespaceDelivery<T, C> {
    pub delivery: mkit_server::purge::PurgeDelivery,
    pub local: LocalCache<C>,
    pub remote: T,
    pub sharding: mkit_server::pipeline::Sharding,
    pub single: Option<mkit_server::RepoId>,
}
impl<S: NamespaceStore, T: NamespaceStore, C: CacheDelete> TimerHandler<S>
    for NamespaceDelivery<T, C>
{
    fn kind(&self) -> TimerKind {
        mkit_server::timers::registry::kinds::CACHE_PURGE
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let local = NamespaceCache {
                local: &self.local,
                source: ctx.store,
                remote: &self.remote,
                partition: ctx.partition,
                sharding: self.sharding,
                single: self.single.as_ref(),
            };
            self.delivery.fire_with_local(&local, ctx, timer).await
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

    #[derive(Clone)]
    struct CatalogCounts {
        inner: Arc<MemoryKv>,
        reads: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    }
    impl NamespaceStore for CatalogCounts {
        fn capabilities(&self) -> mkit_server::StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(
            &self,
            p: &Partition,
            key: &mkit_server::Key,
        ) -> Result<Option<mkit_server::Value>, StoreError> {
            self.inner.get(p, key).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &mkit_server::Key,
            end: &mkit_server::Key,
            after: Option<&mkit_server::Cursor>,
            limit: u32,
        ) -> Result<mkit_server::ScanPage, StoreError> {
            if start.as_bytes() == b"rr\0" {
                self.reads
                    .lock()
                    .unwrap()
                    .push(after.map(|c| c.as_bytes().to_vec()));
            }
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(
            &self,
            p: &Partition,
            batch: Batch,
        ) -> Result<mkit_server::BatchOutcome, StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<mkit_server::PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }

    #[tokio::test]
    #[cfg(feature = "published-view")]
    async fn namespace_catalog_cursor_is_durable_and_never_restarts_prior_pages() {
        use mkit_server::store::{codec, keys};
        let inner = Arc::new(MemoryKv::default());
        let partition = Partition::Coordinator(NamespaceKey::deployment_default());
        for index in 0..20 {
            inner
                .apply(
                    &partition,
                    Batch::new().put(
                        keys::repo_record(&RepoName::new(format!("repo-{index:02}")).unwrap()),
                        codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
                    ),
                )
                .await
                .unwrap();
        }
        let reads = Arc::new(Mutex::new(Vec::new()));
        let source = CatalogCounts {
            inner: inner.clone(),
            reads: reads.clone(),
        };
        let remote_reads = Arc::new(Mutex::new(Vec::new()));
        let remote = CatalogCounts {
            inner: Arc::new(MemoryKv::default()),
            reads: remote_reads.clone(),
        };
        let mut work = request("durable-namespace");
        work.repository.clear();
        work.namespace = "root".into();
        work.url_paths.clear();
        let cache = Cache::default();
        let local = LocalCache {
            cache: cache.clone(),
            snapshot_deployment: Some("fixture-deployment".into()),
        };
        let mut checkpoint = Vec::new();
        let mut charges = 0;
        for _ in 0..200 {
            let budget = SliceBudget::new(6);
            let invalidator = NamespaceCache {
                local: &local,
                source: &source,
                remote: &remote,
                partition: &partition,
                sharding: mkit_server::pipeline::Sharding::D34,
                single: None,
            };
            let next = invalidator
                .invalidate_checkpoint(&work, &checkpoint, &budget)
                .await
                .unwrap();
            charges += budget.used();
            assert!(budget.used() <= 6);
            let Some(next) = next else {
                break;
            };
            checkpoint =
                serde_json::from_slice::<Vec<u8>>(&serde_json::to_vec(&next).unwrap()).unwrap();
        }
        let scans = reads.lock().unwrap();
        assert_eq!(scans.len(), 20);
        assert_eq!(
            scans.iter().filter(|cursor| cursor.is_none()).count(),
            1,
            "cold slices must resume the opaque position"
        );
        assert_eq!(cache.0.lock().unwrap().len(), 20 * 16);
        assert_eq!(
            charges,
            20 + 2 * 20 * 16,
            "every catalog read and delete is reserved"
        );
        assert!(
            remote_reads.lock().unwrap().is_empty(),
            "catalog in this DO must use TimerCtx's local store"
        );
    }

    #[tokio::test]
    #[cfg(feature = "published-view")]
    async fn namespace_checkpoint_exhaustion_corruption_and_single_repo_are_fail_closed() {
        use mkit_server::store::keys;
        let source = CatalogCounts {
            inner: Arc::new(MemoryKv::default()),
            reads: Arc::new(Mutex::new(Vec::new())),
        };
        let remote = source.clone();
        let partition = Partition::Coordinator(NamespaceKey::deployment_default());
        let cache = Cache::default();
        let local = LocalCache {
            cache: cache.clone(),
            snapshot_deployment: Some("fixture-deployment".into()),
        };
        let mut work = request("single-namespace");
        work.repository.clear();
        work.namespace = "root".into();
        work.url_paths.clear();
        let invalidator = NamespaceCache {
            local: &local,
            source: &source,
            remote: &remote,
            partition: &partition,
            sharding: mkit_server::pipeline::Sharding::D34,
            single: None,
        };
        let checkpoint = invalidator
            .invalidate_checkpoint(&work, &[], &SliceBudget::new(0))
            .await
            .unwrap()
            .unwrap();
        assert!(source.reads.lock().unwrap().is_empty());
        assert!(cache.0.lock().unwrap().is_empty());
        for corrupt in [b"invalid".to_vec(), serde_json::json!({"paths":true,"done":true,"after":null,"repository":null,"cursor":0}).to_string().into_bytes(), serde_json::json!({"paths":true,"done":false,"after":null,"repository":"repo","cursor":17}).to_string().into_bytes()] {
            assert!(invalidator.invalidate_checkpoint(&work, &corrupt, &SliceBudget::new(100)).await.is_err());
        }
        source
            .inner
            .apply(
                &partition,
                Batch::new().put(
                    keys::repo_record(&RepoName::new("broken").unwrap()),
                    mkit_server::Value::new(b"invalid".to_vec()),
                ),
            )
            .await
            .unwrap();
        assert!(
            invalidator
                .invalidate_checkpoint(&work, &checkpoint, &SliceBudget::new(100))
                .await
                .is_err()
        );
        assert!(cache.0.lock().unwrap().is_empty());
        let single = mkit_server::RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("configured").unwrap(),
        };
        let single_local = NamespaceCache {
            single: Some(&single),
            ..invalidator
        };
        let prior = source.reads.lock().unwrap().len();
        assert!(
            single_local
                .invalidate_checkpoint(&work, &[], &SliceBudget::new(32))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            source.reads.lock().unwrap().len(),
            prior,
            "Single uses its configured repo, not an absent registry"
        );
        assert_eq!(cache.0.lock().unwrap().len(), 16);
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
            let registry = TimerRegistry::new().register(NamespaceDelivery {
                delivery: PurgeDelivery::new(
                    Arc::new(mkit_server::purge::NoLocalCache),
                    Some(Arc::new(NamespaceSink(delivered.clone()))),
                    budget.clone(),
                ),
                local: LocalCache {
                    cache: cache.clone(),
                    snapshot_deployment: Some("fixture-deployment".into()),
                },
                remote: store.clone(),
                sharding: mkit_server::pipeline::Sharding::D34,
                single: None,
            });
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
        let key = keys::outcome_backlog();
        let backlog = store.get(&partition, &key).await.unwrap().unwrap();
        assert_eq!(
            codec::decode_backlog(&backlog).unwrap(),
            codec::Backlog::default(),
            "purge has fully drained; kind8 still owns its delayed wake"
        );
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
                        snapshot_deployment: Some("deployment".into()),
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
                #[cfg(feature = "published-view")]
                assert_eq!(
                    cache.0.lock().unwrap().len(),
                    if remaining == 64 { 16 } else { 0 }
                );
                #[cfg(not(feature = "published-view"))]
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
