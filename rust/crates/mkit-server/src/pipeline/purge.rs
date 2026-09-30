use super::{Pipeline, meta_error};
use crate::pipeline::HookSet;
use crate::purge::{Request, Trigger, plan_enqueue};
use crate::store::{Batch, MultipartBlobStore, NamespaceStore, Partition, keys};
use crate::{RepoId, ServerError};
use mkit_core::hash::{hash, to_hex};

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
        let Some(config) = &self.cfg.purge else {
            return Ok(Batch::new());
        };
        let repository = format!("{}/{}", repo.namespace.as_str(), repo.name.as_str());
        let request = Request {
            purge_id: format!(
                "purge:{}",
                to_hex(&hash(
                    format!(
                        "{}\0{repository}\0{trigger:?}\0{operation_id}",
                        config.audience
                    )
                    .as_bytes()
                ))
            ),
            audience: config.audience.clone(),
            repository,
            namespace: String::new(),
            trigger,
            url_paths: Vec::new(),
            object_ids: Vec::new(),
            refs: Vec::new(),
        };
        let audit = config.audit.as_ref().ok_or_else(|| {
            ServerError::failed_precondition("automatic purge requires durable audit")
        })?;
        let mut batch = audit
            .plan(partition, &request, operation_id, now_ms)
            .await
            .map_err(meta_error)?;
        let values = self
            .meta
            .get_many(
                partition,
                &[
                    keys::outcome_backlog(),
                    keys::cache_purge_generation(request.scope()),
                ],
            )
            .await
            .map_err(meta_error)?;
        let work = plan_enqueue(&request, now_ms, values[0].as_ref(), values[1].as_ref())
            .map_err(meta_error)?;
        batch.preconditions.extend(work.preconditions);
        batch.writes.extend(work.writes);
        Ok(batch)
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
                self.seen.lock().unwrap().push(request.clone());
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
            crate::upload::UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 32,
            },
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
