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
    pub async fn plan_repository_purge(&self, partition: &Partition, repo: &RepoId, trigger: Trigger, operation_id: &str, now_ms: u64) -> Result<Batch, ServerError> {
        let Some(config) = &self.cfg.purge else { return Ok(Batch::new()); };
        let repository = format!("{}/{}", repo.namespace.as_str(), repo.name.as_str());
        let request = Request {
            purge_id: format!("purge:{}", to_hex(&hash(format!("{}\0{repository}\0{trigger:?}\0{operation_id}", config.audience).as_bytes()))),
            audience: config.audience.clone(), repository, namespace: String::new(), trigger,
            url_paths: Vec::new(), object_ids: Vec::new(), refs: Vec::new(),
        };
        let audit = config.audit.as_ref().ok_or_else(|| ServerError::failed_precondition("automatic purge requires durable audit"))?;
        let mut batch = audit.plan(partition, &request, now_ms).await.map_err(meta_error)?;
        let values = self.meta.get_many(partition, &[keys::outcome_backlog(), keys::cache_purge_generation(request.scope())]).await.map_err(meta_error)?;
        let work = plan_enqueue(&request, now_ms, values[0].as_ref(), values[1].as_ref()).map_err(meta_error)?;
        batch.preconditions.extend(work.preconditions);
        batch.writes.extend(work.writes);
        Ok(batch)
    }
    /// Immediately forget positive local reachability proofs after a serving stop.
    pub fn invalidate_local_cache(&self, repo: &RepoId) {
        #[cfg(feature = "http-objects")]
        if let Some(seams) = &self.http_seams { seams.reachability.invalidate(repo); }
        #[cfg(not(feature = "http-objects"))]
        let _ = repo;
    }
}
