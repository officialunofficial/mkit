use super::{Pipeline, meta_error};
use crate::pipeline::HookSet;
#[cfg(all(test, feature = "memory"))]
use crate::purge::plan_enqueue;
use crate::purge::{Request, Trigger};
#[cfg(all(test, feature = "memory"))]
use crate::store::keys;
use crate::store::{Batch, MultipartBlobStore, NamespaceStore, Partition};
use crate::{RepoId, ServerError};

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Plan an audited safety purge in the same batch as a serving stop.
    /// `operation_id` is stable across retries of the automatic action.
    /// Callers merge this batch into the authoritative state mutation.
    pub async fn plan_repository_purge(
        &self,
        partition: &Partition,
        repo: &RepoId,
        trigger: Trigger,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<Batch, ServerError> {
        crate::purge::automatic::plan_repository(
            self.cfg.purge.as_ref(),
            &self.meta,
            partition,
            repo,
            trigger,
            operation_id,
            now_ms,
        )
        .await
        .map_err(meta_error)
    }
    /// Immediately invalidate local entries after committing a serving stop and
    /// its durable purge work. Timer 11 retries any failed cache deletion.
    pub async fn invalidate_local_cache(&self, repo: &RepoId) {
        #[cfg(feature = "http-objects")]
        if let Some(seams) = &self.http_seams {
            seams.reachability.invalidate(repo);
        }
        if let Some(config) = &self.cfg.purge
            && let Some(local) = &config.local
        {
            let request = Request {
                purge_id: "local".into(),
                audience: config.audience.clone(),
                repository: format!("{}/{}", repo.namespace.as_str(), repo.name.as_str()),
                namespace: String::new(),
                trigger: Trigger::Suspension,
                url_paths: Vec::new(),
                object_ids: Vec::new(),
                refs: Vec::new(),
            };
            // The state change, immutable purge work and timer already committed.
            // Failed or incomplete immediate deletes remain pending in kind 11.
            let _ = local
                .invalidate(&request, 0, &crate::purge::SliceBudget::new(64))
                .await;
        }
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::purge::{LocalInvalidation, PurgeConfig, SliceBudget};
    use crate::{
        Addressing, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, RepoName, StoreError,
    };
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn automatic_purge_identity_is_source_partition_bound_and_retry_stable() {
        let store = Arc::new(MemoryKv::default());
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("repo").unwrap(),
        };
        let coordinator = Partition::Coordinator(repo.namespace.clone());
        let index = Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: 1,
        };
        let mut config = crate::pipeline::PipelineConfig::new(
            Addressing::Single { repo: repo.clone() },
            crate::pipeline::AuthMode::Open,
            crate::upload::UploadLimits::new(1024, 32),
        );
        config.purge = Some(
            PurgeConfig::new("https://server.example".into(), true, true).with_audit(Arc::new(
                crate::admin::SystemAudit::new(store.clone(), coordinator.clone()),
            )),
        );
        let pipeline = Pipeline::new(
            MemoryBlobStore::default(),
            store,
            crate::pipeline::Hooks::new(),
            config,
            Arc::new(ManualClock::new(10)),
            Arc::new(crate::NoopMetrics),
        )
        .unwrap();
        let mut requests = Vec::new();
        for partition in [&coordinator, &index, &coordinator] {
            let batch = pipeline
                .plan_repository_purge(partition, &repo, Trigger::Suspension, "same-op", 10)
                .await
                .unwrap();
            requests.push(
                batch
                    .writes
                    .iter()
                    .find_map(|write| match write {
                        crate::Write::Put(key, value) if key.as_bytes().starts_with(b"cp\0") => {
                            Some(
                                serde_json::from_slice::<Request>(value.as_bytes())
                                    .expect("planned purge request"),
                            )
                        }
                        _ => None,
                    })
                    .unwrap(),
            );
        }
        assert_ne!(requests[0].purge_id, requests[1].purge_id);
        assert_eq!(requests[0].purge_id, requests[2].purge_id);
    }
    struct FailingLocal {
        store: Arc<MemoryKv>,
        partition: Partition,
        seen: Arc<Mutex<Vec<Request>>>,
    }
    impl LocalInvalidation for FailingLocal {
        fn invalidate<'a>(
            &'a self,
            request: &'a Request,
            _: u32,
            _: &'a SliceBudget,
        ) -> crate::BoxFuture<'a, Result<Option<u32>, StoreError>> {
            Box::pin(async move {
                assert!(
                    crate::purge::read_request(&self.store, &self.partition, "committed")
                        .await?
                        .is_some()
                );
                self.seen
                    .lock()
                    .expect("local invalidation recording lock")
                    .push(request.clone());
                Err(StoreError::unavailable("local cache offline"))
            })
        }
    }
    #[tokio::test]
    async fn immediate_local_failure_keeps_committed_intent_and_timer_for_retry() {
        let store = Arc::new(MemoryKv::default());
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("repo").unwrap(),
        };
        let partition = Partition::Namespace(repo.namespace.clone());
        let request = Request {
            purge_id: "committed".into(),
            audience: "https://server.example".into(),
            repository: "root/repo".into(),
            namespace: String::new(),
            trigger: Trigger::Suspension,
            url_paths: Vec::new(),
            object_ids: Vec::new(),
            refs: Vec::new(),
        };
        store
            .apply(&partition, plan_enqueue(&request, 10, None, None).unwrap())
            .await
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = crate::pipeline::PipelineConfig::new(
            Addressing::Single { repo: repo.clone() },
            crate::pipeline::AuthMode::Open,
            crate::upload::UploadLimits::new(1024, 32),
        );
        config.purge = Some(
            PurgeConfig::new(request.audience.clone(), true, true).with_local(Arc::new(
                FailingLocal {
                    store: store.clone(),
                    partition: partition.clone(),
                    seen: seen.clone(),
                },
            )),
        );
        let pipeline = Pipeline::new(
            MemoryBlobStore::default(),
            store.clone(),
            crate::pipeline::Hooks::new(),
            config,
            Arc::new(ManualClock::new(10)),
            Arc::new(crate::NoopMetrics),
        )
        .unwrap();
        pipeline.invalidate_local_cache(&repo).await;
        assert_eq!(seen.lock().unwrap()[0].repository, "root/repo");
        assert!(
            crate::purge::read_request(&store, &partition, "committed")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get(&partition, &keys::timer(10, 11, b"committed"))
                .await
                .unwrap()
                .is_some()
        );
    }
}
