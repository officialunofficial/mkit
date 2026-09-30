//! Conservative invalidation through the existing published-source seam.
use mkit_server::pipeline::{
    Sharding,
    published::{PublishedBucket, PublishedSource},
};
use mkit_server::{BoxFuture, NamespaceStore, Partition, RepoId, StoreError, purge, store::keys};
use std::sync::Arc;

struct FencedReader<S> {
    source: Arc<dyn PublishedSource>,
    store: S,
    sharding: Sharding,
}
impl<S: NamespaceStore> FencedReader<S> {
    async fn invalidated(&self, repo: &RepoId) -> Result<bool, StoreError> {
        let partition = match self.sharding {
            Sharding::Single => Partition::Namespace(repo.namespace.clone()),
            _ => Partition::Coordinator(repo.namespace.clone()),
        };
        let values = self
            .store
            .get_many(
                &partition,
                &[
                    keys::cache_purge_generation(&format!(
                        "{}/{}",
                        repo.namespace.as_str(),
                        repo.name.as_str()
                    )),
                    keys::cache_purge_generation(repo.namespace.as_str()),
                ],
            )
            .await?;
        Ok(values
            .iter()
            .map(|v| purge::generation(v.as_ref()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|g| g > 0))
    }
}
impl<S: NamespaceStore> PublishedSource for FencedReader<S> {
    fn inspection_configured(&self) -> bool {
        self.source.inspection_configured()
    }
    fn uses_published_values(&self) -> bool {
        self.source.uses_published_values()
    }
    fn read_ref_enabled(&self) -> bool {
        self.source.read_ref_enabled()
    }
    fn bucket<'a>(
        &'a self,
        repo: &'a RepoId,
        partition: &'a Partition,
        now_ms: u64,
    ) -> BoxFuture<'a, PublishedBucket> {
        Box::pin(async move {
            if self.source.inspection_configured() && !self.source.uses_published_values() {
                return Err(StoreError::unavailable("published view unavailable"));
            }
            if self.invalidated(repo).await? {
                return Ok(None);
            }
            let rows = self.source.bucket(repo, partition, now_ms).await?;
            // A source may fill Cache from retained R2 bytes during this await.
            // The final strong read prevents that refill from bypassing a purge.
            if self.invalidated(repo).await? {
                return Ok(None);
            }
            Ok(rows)
        })
    }
}
/// Fence snapshots when automatic purges are enabled. An invalidated scope uses
/// live published reads until a generation-aware publisher can certify freshness.
/// Unconfigured deployments retain the original snapshot cost and behavior.
pub fn fenced_reader<S: NamespaceStore + 'static>(
    source: Arc<dyn PublishedSource>,
    store: S,
    sharding: Sharding,
) -> Arc<dyn PublishedSource> {
    Arc::new(FencedReader {
        source,
        store,
        sharding,
    })
}
